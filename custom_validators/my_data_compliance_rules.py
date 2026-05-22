from nautobot_data_validation_engine.custom_validators import (
    DataComplianceRule,
    ComplianceError,
)


class VLANMinMaxComplianceRule(DataComplianceRule):
    model = "ipam.vlan"
    enforce = False  # Report only, don't block changes

    MIN_VLAN = 11
    MAX_VLAN = 500

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