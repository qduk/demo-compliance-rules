from nautobot_data_validation_engine.custom_validators import (
    DataComplianceRule,
    ComplianceError,
    CustomValidatorIterator
)


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
        
custom_validators = list(CustomValidatorIterator()) + [VLANMinMaxComplianceRule]