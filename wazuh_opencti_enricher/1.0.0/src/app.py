# /Shuffle/shuffle-apps/wazuh_opencti_enricher/1.0.0/src/app.py

# coding: utf-8

from pycti import OpenCTIApiClient
# pycti kütüphanesinin özel istisnalarını import ediyoruz
from pycti.utils.opencti_exceptions import (
    OpenCTIAPIException,
    OpenCTIConnectionError,
    OpenCTIAuthenticationError,
    OpenCTIInternalError,
    OpenCTIInvalidParam,
    OpenCTIUnauthorized
)

import json
import sys
import os
from datetime import datetime
import logging
# Cortex örneğindeki gibi walkoff_app_sdk kullanıyoruz
from walkoff_app_sdk.app_base import AppBase

# Eğer TLS/SSL uyarılarını kapatmak gerekiyorsa bu import eklenmeli
import urllib3

# --- Shuffle Uygulama Sınıfı ---
class WazuhOpenCTIEnricherApp(AppBase):
    __version__ = "1.0.0" # Uygulama versiyonu
    app_name = "Wazuh OpenCTI Enricher" # api.yaml'daki 'name' ile eşleşmeli

    def __init__(self, redis, logger, console_logger=None):
        """
        Her Shuffle uygulaması bu __init__ metoduna sahip olmalıdır.
        :param redis: Redis bağlantısı (Shuffle tarafından sağlanır)
        :param logger: Shuffle'ın ana logger'ı (Shuffle tarafından sağlanır)
        :param console_logger: Konsol çıktısı için logger (isteğe bağlı)
        """
        super().__init__(redis, logger, console_logger)
        self.opencti_api_client = None # OpenCTI client'ı burada başlatılacak

        # Pycti loglarını azaltın
        pycti_logger = logging.getLogger('pycti')
        pycti_logger.setLevel(logging.WARNING)

        # Cortex örneğindeki gibi SSL/TLS uyarılarını kapatmak için ekleme
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # --- Yardımcı Fonksiyon: OpenCTI Bağlantısı ---
    def _initialize_opencti_client(self, api_url, api_token):
        if self.opencti_api_client:
            return self.opencti_api_client

        try:
            # OpenCTIApiClient'a ssl_verify=False parametresini ekliyoruz
            self.opencti_api_client = OpenCTIApiClient(api_url, api_token, ssl_verify=False)
            self.logger.info(f"OpenCTI API client initialized successfully.")
            return self.opencti_api_client
        except OpenCTIConnectionError as e:
            self.logger.error(f"OpenCTI bağlantı hatası: {e}", exc_info=True)
            raise OpenCTIConnectionError(f"OpenCTI'ye bağlanılamadı: {e}")
        except OpenCTIAuthenticationError as e:
            self.logger.error(f"OpenCTI kimlik doğrulama hatası: {e}", exc_info=True)
            raise OpenCTIAuthenticationError(f"OpenCTI kimlik doğrulaması başarısız: {e}")
        except OpenCTIAPIException as e:
            self.logger.error(f"OpenCTI API hatası: {e}", exc_info=True)
            raise OpenCTIAPIException(f"OpenCTI API'den hata döndü: {e}")
        except Exception as e:
            self.logger.error(f"Beklenmedik OpenCTI istemci başlatma hatası: {e}", exc_info=True)
            raise Exception(f"OpenCTI istemci başlatılırken beklenmedik bir hata oluştu: {e}")

    # --- Yardımcı Fonksiyon: OpenCTI Zenginleştirmesi ---
    def _enrich_observable_from_opencti(self, observable_type, observable_value):
        self.logger.info(f"\nAttempting to enrich {observable_type}: '{observable_value}'")

        search_key = ""
        if observable_type == "IPv4-Addr":
            search_key = "value"
        elif observable_type == "File.name":
            search_key = "name"
        elif observable_type == "File.hashes.MD5":
            search_key = "hashes.MD5"
        else:
            self.logger.error(f"Unsupported observable type for search: {observable_type}")
            return None

        try:
            observable = self.opencti_api_client.stix_cyber_observable.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": search_key, "values": [observable_value]}],
                    "filterGroups": [],
                }
            )

            if observable:
                self.logger.info(f"Found {observable_type} observable in OpenCTI.")
                enriched_data = {
                    "type": observable.get('entity_type'),
                }

                if observable_type == "IPv4-Addr":
                    enriched_data["value"] = observable.get('value')
                elif observable_type == "File.name":
                    enriched_data["name"] = observable.get('name')
                elif observable_type == "File.hashes.MD5":
                    md5_hash_found = next((h['hash'] for h in observable.get('hashes', []) if h.get('algorithm') == 'MD5'), None)
                    enriched_data["md5_hash"] = md5_hash_found if md5_hash_found else 'N/A'

                enriched_data.update({
                    "opencti_id": observable.get('id'),
                    "description": observable.get('x_opencti_description', 'N/A'),
                    "score": observable.get('x_opencti_score', 'N/A'),
                    "created_by": observable.get('createdBy', {}).get('name', 'N/A'),
                    "labels": [label.get('value', '') for label in observable.get('objectLabel', []) if label.get('value')],
                    "marking": ", ".join([marking.get('definition', '') for marking in observable.get('objectMarking', []) if marking.get('definition')])
                })

                return enriched_data
            else:
                self.logger.info(f"No existing {observable_type} observable found for value: '{observable_value}' in OpenCTI.")
                return None

        except (OpenCTIConnectionError, OpenCTIAuthenticationError, OpenCTIAPIException) as e:
            self.logger.error(f"OpenCTI arama hatası for '{observable_value}': {e}", exc_info=True)
            return {"error": f"OpenCTI arama hatası: {e}"} # Hata objesi döndür
        except Exception as e:
            self.logger.error(f"Beklenmedik bir hata oluştu OpenCTI araması sırasında for '{observable_value}': {e}", exc_info=True)
            return {"error": f"Beklenmedik hata: {e}"} # Hata objesi döndür

    # --- Yardımcı Fonksiyon: Wazuh Alert'ten Göstergeleri Çıkarma ---
    def _extract_indicators_from_wazuh_alert(self, alert_content):
        indicators = {
            "ips": [],
            "file_names": [],
            "md5_hashes": []
        }

        base_data = alert_content.get('all_fields', alert_content)

        # --- IP Address Extraction ---
        possible_ips = []
        if base_data.get('agent', {}).get('ip') and isinstance(base_data['agent']['ip'], str):
            possible_ips.append(base_data['agent']['ip'])
        if base_data.get('network', {}).get('source_ip') and isinstance(base_data['network']['source_ip'], str):
            possible_ips.append(base_data['network']['source_ip'])
        if base_data.get('network', {}).get('destination_ip') and isinstance(base_data['network']['destination_ip'], str):
            possible_ips.append(base_data['network']['destination_ip'])
        if base_data.get('data', {}).get('srcip') and isinstance(base_data['data']['srcip'], str):
            possible_ips.append(base_data['data']['srcip'])
        if base_data.get('data', {}).get('dstip') and isinstance(base_data['data']['dstip'], str):
            possible_ips.append(base_data['data']['dstip'])
        indicators['ips'] = list(set(ip for ip in possible_ips if ip))

        # --- File Name and MD5 Hash Extraction ---
        possible_file_names = []
        possible_md5_hashes = []

        virustotal_source = base_data.get('data', {}).get('virustotal', {}).get('source', {})
        if virustotal_source:
            file_path_vt = virustotal_source.get('file')
            if file_path_vt and isinstance(file_path_vt, str):
                possible_file_names.append(os.path.basename(file_path_vt))
            if virustotal_source.get('md5') and isinstance(virustotal_source['md5'], str):
                possible_md5_hashes.append(virustotal_source['md5'])

        file_path_direct = base_data.get('file')
        if file_path_direct and isinstance(file_path_direct, str):
            possible_file_names.append(os.path.basename(file_path_direct))
        md5_direct = base_data.get('md5')
        if md5_direct and isinstance(md5_direct, str):
            possible_md5_hashes.append(md5_direct)

        file_info_objects = [base_data.get('file_info', {}), base_data.get('file', {})]
        for file_obj in file_info_objects:
            if file_obj and isinstance(file_obj, dict):
                if file_obj.get('name') and isinstance(file_obj['name'], str):
                    possible_file_names.append(file_obj['name'])
                hashes_obj = file_obj.get('hash', {})
                if hashes_obj and isinstance(hashes_obj, dict):
                    if hashes_obj.get('md5') and isinstance(hashes_obj['md5'], str):
                        possible_md5_hashes.append(hashes_obj['md5'])

        indicators['file_names'] = list(set(fn for fn in possible_file_names if fn))
        indicators['md5_hashes'] = list(set(md5 for md5 in possible_md5_hashes if md5))

        return indicators

    # --- ANA EYLEM FONKSİYONU (api.yaml'da tanımlı) ---
    def enrich_alert_with_opencti(self, opencti_url, opencti_token, wazuh_alert_json):
        """
        Shuffle'dan çağrılan ana eylem fonksiyonu.
        Wazuh alarmını OpenCTI ile zenginleştirir.
        """
        self.logger.info("Starting OpenCTI Enrichment Script for Wazuh Alerts")
        self.logger.info("Parsing Wazuh alert JSON...")

        try:
            # wazuh_alert_json Shuffle'dan bir string olarak gelir, bu yüzden JSON'a dönüştürülmeli
            wazuh_alert = json.loads(wazuh_alert_json)
        except json.JSONDecodeError as e:
            self.logger.critical(f"Failed to parse Wazuh alert JSON. Please ensure it's valid JSON. Details: {e}", exc_info=True)
            # Hata durumunda boş veya hata içeren bir çıktı döndür
            return json.dumps({"error": f"Invalid JSON input: {e}"})

        # OpenCTI istemcisini başlat
        try:
            self._initialize_opencti_client(opencti_url, opencti_token)
        except Exception as e: # Burada daha spesifik hata yakalamak daha iyi
            return json.dumps({"error": f"OpenCTI client initialization failed: {e}"})

        # Wazuh alert içeriğini yönetin (top-level wrapping)
        wazuh_alert_content = wazuh_alert
        if isinstance(wazuh_alert, dict) and len(wazuh_alert) == 1:
            first_key = next(iter(wazuh_alert))
            if first_key.startswith('Results for '):
                wazuh_alert_content = wazuh_alert[first_key]
                self.logger.info(f"Unwrapped top-level key: '{first_key}'")
            elif first_key == 'all_fields' and isinstance(wazuh_alert[first_key], dict):
                wazuh_alert_content = wazuh_alert[first_key]
                self.logger.info(f"'all_fields' detected as direct root.")

        self.logger.info("\n=== Indicator Extraction Phase ===")
        extracted_indicators = self._extract_indicators_from_wazuh_alert(wazuh_alert_content)

        # Eğer _extract_indicators_from_wazuh_alert hata objesi döndürürse, burada kontrol et
        if isinstance(extracted_indicators, dict) and "error" in extracted_indicators:
            return json.dumps(extracted_indicators)

        self.logger.info(f"Extracted {len(extracted_indicators['ips'])} unique IP(s).")
        for ip in extracted_indicators['ips']:
            self.logger.info(f"  - IP: '{ip}'")

        self.logger.info(f"Extracted {len(extracted_indicators['file_names'])} unique File Name(s).")
        for fn in extracted_indicators['file_names']:
            self.logger.info(f"  - File Name: '{fn}'")

        self.logger.info(f"Extracted {len(extracted_indicators['md5_hashes'])} unique MD5 Hash(es).")
        for md5 in extracted_indicators['md5_hashes']:
            self.logger.info(f"  - MD5 Hash: '{md5}'")

        self.logger.info("\n=== OpenCTI Enrichment Phase ===")
        enriched_observables_list = []

        # İşlem extracted IP adresleri
        for ip in extracted_indicators.get('ips', []):
            enriched_data = self._enrich_observable_from_opencti("IPv4-Addr", ip)
            # Eğer enriched_data bir hata objesi ise, onu da listeye ekleyebiliriz veya atlayabiliriz
            if enriched_data and "error" in enriched_data:
                self.logger.warning(f"IP {ip} için zenginleştirme hatası: {enriched_data['error']}")
                enriched_observables_list.append({"observable": ip, "type": "IPv4-Addr", "status": "failed", "error": enriched_data['error']})
            elif enriched_data:
                enriched_observables_list.append(enriched_data)

        # İşlem extracted Dosya Adları
        for file_name_val in extracted_indicators.get('file_names', []):
            enriched_data = self._enrich_observable_from_opencti("File.name", file_name_val)
            if enriched_data and "error" in enriched_data:
                self.logger.warning(f"Dosya adı {file_name_val} için zenginleştirme hatası: {enriched_data['error']}")
                enriched_observables_list.append({"observable": file_name_val, "type": "File.name", "status": "failed", "error": enriched_data['error']})
            elif enriched_data:
                enriched_observables_list.append(enriched_data)

        # İşlem extracted MD5 Hash'leri
        for md5_hash_val in extracted_indicators.get('md5_hashes', []):
            enriched_data = self._enrich_observable_from_opencti("File.hashes.MD5", md5_hash_val)
            if enriched_data and "error" in enriched_data:
                self.logger.warning(f"MD5 hash {md5_hash_val} için zenginleştirme hatası: {enriched_data['error']}")
                enriched_observables_list.append({"observable": md5_hash_val, "type": "File.hashes.MD5", "status": "failed", "error": enriched_data['error']})
            elif enriched_data:
                enriched_observables_list.append(enriched_data)

        self.logger.info(f"\nTotal {len(enriched_observables_list)} observables enriched from OpenCTI.")
        self.logger.info("=== Generating Final JSON Output ===")

        # Nihai JSON çıktısını hazırla
        final_output = {
            "original_alert": wazuh_alert,
            "enriched_observables": enriched_observables_list
        }

        self.logger.info("Script finished. JSON output prepared.")
        # Shuffle'a JSON string olarak döndür
        return json.dumps(final_output, indent=2)

# Uygulama SDK'sını başlatmak için gereken satır
if __name__ == "__main__":
    WazuhOpenCTIEnricherApp.run()
