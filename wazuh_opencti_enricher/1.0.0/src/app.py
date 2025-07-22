# coding: utf-8

import json
import sys
import logging
import os
from datetime import datetime
# AppBase is required for Shuffle Custom Apps
from walkoff_app_sdk.app_base import AppBase

# --- Shuffle App Class ---
class WazuhOpenCTIEnricherApp(AppBase):
    __version__ = "1.0.0" # Application version
    app_name = "iocs_opencti" # Must match 'name' in api.yaml

    def __init__(self, redis, logger, console_logger=None):
        """
        Every Shuffle application must have this __init__ method.
        :param redis: Redis connection (provided by Shuffle)
        :param logger: Shuffle's main logger (provided by Shuffle)
        :param console_logger: Logger for console output (optional)
        """
        super().__init__(redis, logger, console_logger)
        # OpenCTI client is not needed for this test, but keeping the structure
        # for future OpenCTI integration.
        self.opencti_api_client = None 

    # --- MAIN ACTION FUNCTION (defined in api.yaml) ---
    def enrich_alert_with_opencti(self, wazuh_alert_json, ioc_data_from_parser):
        """
        The main action function called by Shuffle.
        This test function will simply parse and return the inputs.
        """
        self.logger.info("Starting Wazuh OpenCTI Enricher Test Script.")
        self.logger.info("Parsing inputs received from Shuffle...")

        original_alert = {}
        parsed_ioc_item = {}
        
        # Parse wazuh_alert_json (which comes as a string from Shuffle)
        try:
            original_alert = json.loads(wazuh_alert_json)
            self.logger.info("Wazuh alert JSON parsed successfully.")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse wazuh_alert_json. Ensure it's valid JSON. Details: {e}", exc_info=True)
            original_alert = {"error": f"Invalid JSON for wazuh_alert_json: {e}"}
        
        # Parse ioc_data_from_parser (which comes as a string from Shuffle)
        try:
            parsed_ioc_item = json.loads(ioc_data_from_parser)
            self.logger.info("IOC data from parser JSON parsed successfully.")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse ioc_data_from_parser. Ensure it's valid JSON. Details: {e}", exc_info=True)
            parsed_ioc_item = {"error": f"Invalid JSON for ioc_data_from_parser: {e}"}

        self.logger.info("\n=== Test Output ===")
        self.logger.info(f"Received Wazuh Alert (parsed): {json.dumps(original_alert, indent=2)}")
        self.logger.info(f"Received IOC Item from Parser (parsed): {json.dumps(parsed_ioc_item, indent=2)}")
        self.logger.info(f"Type of parsed_ioc_item: {type(parsed_ioc_item)}")
        
        # Prepare the final JSON output for Shuffle
        final_output = {
            "success": True,
            "message": "Test completed successfully. Inputs received and parsed.",
            "received_wazuh_alert": original_alert,
            "received_ioc_item": parsed_ioc_item,
            "ioc_item_type": str(type(parsed_ioc_item)),
            "ioc_item_data_field": parsed_ioc_item.get("data", "N/A") if isinstance(parsed_ioc_item, dict) else "N/A",
            "ioc_item_data_type_field": parsed_ioc_item.get("data_type", "N/A") if isinstance(parsed_ioc_item, dict) else "N/A",
        }

        self.logger.info("Script finished. JSON output prepared.")
        # Return the JSON string to Shuffle
        return json.dumps(final_output, indent=2)

# Required line to start the App SDK
if __name__ == "__main__":
    WazuhOpenCTIEnricherApp.run()
