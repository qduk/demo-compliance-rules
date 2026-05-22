from nautobot_data_validation_engine.custom_validators import (
    DataComplianceRule,
    ComplianceError,
    CustomValidatorIterator
)
import re


class VLANMinMaxComplianceRule(DataComplianceRule):
    model = "ipam.vlan"
    enforce = False

    MIN_VLAN = 11
    MAX_VLAN = 25

    def audit(self):
        vlan = self.context["object"]

        if vlan.vid < self.MIN_VLAN or vlan.vid > self.MAX_VLAN:
            raise ComplianceError(
                {
                    "vid": (
                        f"VLAN ID {vlan.vid} is out of compliance; "
                        f"must be between {self.MIN_VLAN} and {self.MAX_VLAN}."
                    )
                }
            )
        
class DeviceDataComplianceRules(DataComplianceRule):
    model = "dcim.device"
    enforce = False

    # Checks if a device name contains any special characters other than a dash (-), underscore (_), or period (.) using regex
    def audit_device_name_chars(self):
        if not re.match("^[a-zA-Z0-9\-_.]+$", self.context["object"].name):
            raise ComplianceError({"name": "Device name contains unallowed special characters."})

    def audit(self):
        messages = {}
        for fn in [self.audit_device_name_chars]:
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)

class RackDeviceComplianceRules(DataComplianceRule):
    model = "dcim.device"
    enforce = False

    # Checks if a device is not assigned to a rack
    def audit_device_rack(self):
        if not self.context["object"].rack:
            raise ComplianceError({"rack": "Device should be assigned to a rack."})

    def audit(self):
        messages = {}
        for fn in [self.audit_device_rack]:
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)