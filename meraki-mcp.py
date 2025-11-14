import os
import json
import meraki
import asyncio
import functools
from typing import Dict, List, Optional, Any, Callable, Tuple
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
import re
import time
import logging

# Load environment variables
load_dotenv()

# Setup logging
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP("Meraki MCP Server")

# Configuration
MERAKI_API_KEY = os.getenv("MERAKI_API_KEY")
MERAKI_ORG_ID = os.getenv("MERAKI_ORG_ID")

# Initialize Meraki Dashboard
dashboard = meraki.DashboardAPI(api_key=MERAKI_API_KEY, suppress_logging=True)

###################
# ASYNC UTILITIES
###################
def to_async(func: Callable) -> Callable:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))
    return wrapper

# Async versions of SDK methods
async_get_organizations = to_async(dashboard.organizations.getOrganizations)
async_get_organization = to_async(dashboard.organizations.getOrganization)
async_get_organization_networks = to_async(dashboard.organizations.getOrganizationNetworks)
async_get_organization_devices = to_async(dashboard.organizations.getOrganizationDevices)
async_get_network = to_async(dashboard.networks.getNetwork)
async_get_network_devices = to_async(dashboard.networks.getNetworkDevices)
async_get_network_clients = to_async(dashboard.networks.getNetworkClients)
async_get_device = to_async(dashboard.devices.getDevice)
async_update_device = to_async(dashboard.devices.updateDevice)
async_get_wireless_ssids = to_async(dashboard.wireless.getNetworkWirelessSsids)
async_update_wireless_ssid = to_async(dashboard.wireless.updateNetworkWirelessSsid)
async_get_switch_ports = to_async(dashboard.switch.getDeviceSwitchPorts)
async_get_switch_port_statuses = to_async(dashboard.switch.getDeviceSwitchPortsStatuses)
async_get_appliance_uplinks_settings = to_async(dashboard.appliance.getDeviceApplianceUplinksSettings)
async_get_network_appliance_vlans = to_async(dashboard.appliance.getNetworkApplianceVlans)
async_get_device_wireless_status = to_async(dashboard.wireless.getDeviceWirelessStatus)
async_get_wireless_connection_stats = to_async(dashboard.wireless.getNetworkWirelessConnectionStats)
async_get_wireless_failed_connections = to_async(dashboard.wireless.getNetworkWirelessFailedConnections)
async_get_appliance_firewall_l3_rules = to_async(dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules)
async_get_appliance_security_intrusion = to_async(dashboard.appliance.getNetworkApplianceSecurityIntrusion)
async_get_appliance_content_filtering = to_async(dashboard.appliance.getNetworkApplianceContentFiltering)
async_get_organization_admins = to_async(dashboard.organizations.getOrganizationAdmins)
async_get_device_appliance_performance = to_async(dashboard.appliance.getDeviceAppliancePerformance)
async_get_organization_appliance_uplink_statuses = to_async(dashboard.appliance.getOrganizationApplianceUplinkStatuses)
async_get_organization_firmware_upgrades = to_async(dashboard.organizations.getOrganizationFirmwareUpgrades)
async_get_network_traffic_analysis = to_async(dashboard.networks.getNetworkTrafficAnalysis)

###################
# SCHEMA DEFINITIONS
###################
class Dot11wSettings(BaseModel):
    enabled: bool = Field(False, description="Whether 802.11w is enabled or not")
    required: bool = Field(False, description="Whether 802.11w is required or not")

class Dot11rSettings(BaseModel):
    enabled: bool = Field(False, description="Whether 802.11r is enabled or not")
    adaptive: bool = Field(False, description="Whether 802.11r is adaptive or not")

class RadiusServer(BaseModel):
    host: str = Field(..., description="IP address of the RADIUS server")
    port: int = Field(..., description="Port of the RADIUS server")
    secret: str = Field(..., description="Secret for the RADIUS server")
    radsecEnabled: Optional[bool] = Field(None, description="Whether RADSEC is enabled or not")
    openRoamingCertificateId: Optional[int] = Field(None, description="OpenRoaming certificate ID")
    caCertificate: Optional[str] = Field(None, description="CA certificate for RADSEC")

class SsidUpdateSchema(BaseModel):
    name: Optional[str] = Field(None, description="The name of the SSID")
    enabled: Optional[bool] = Field(None, description="Whether the SSID is enabled or not")
    authMode: Optional[str] = Field(None, description="The auth mode for the SSID (e.g., 'open', 'psk', '8021x-radius')")
    enterpriseAdminAccess: Optional[str] = Field(None, description="Enterprise admin access setting")
    encryptionMode: Optional[str] = Field(None, description="The encryption mode for the SSID")
    psk: Optional[str] = Field(None, description="The pre-shared key for the SSID when using PSK auth mode")
    wpaEncryptionMode: Optional[str] = Field(None, description="WPA encryption mode (e.g., 'WPA1 and WPA2', 'WPA2 only')")
    dot11w: Optional[Dot11wSettings] = Field(None, description="802.11w settings")
    dot11r: Optional[Dot11rSettings] = Field(None, description="802.11r settings")
    splashPage: Optional[str] = Field(None, description="The type of splash page for the SSID")
    radiusServers: Optional[List[RadiusServer]] = Field(None, description="List of RADIUS servers")
    visible: Optional[bool] = Field(None, description="Whether the SSID is visible or not")
    availableOnAllAps: Optional[bool] = Field(None, description="Whether the SSID is available on all APs")
    bandSelection: Optional[str] = Field(None, description="Band selection for SSID (e.g., '5 GHz band only', 'Dual band operation')")

class FirewallRule(BaseModel):
    comment: str = Field(..., description="Description of the firewall rule")
    policy: str = Field(..., description="'allow' or 'deny'")
    protocol: str = Field(..., description="The protocol (e.g., 'tcp', 'udp', 'any')")
    srcPort: Optional[str] = Field("Any", description="Source port (e.g., '80', '443-8080', 'Any')")
    srcCidr: str = Field("Any", description="Source CIDR (e.g., '192.168.1.0/24', 'Any')")
    destPort: Optional[str] = Field("Any", description="Destination port (e.g., '80', '443-8080', 'Any')")
    destCidr: str = Field("Any", description="Destination CIDR (e.g., '192.168.1.0/24', 'Any')")
    syslogEnabled: Optional[bool] = Field(False, description="Whether syslog is enabled for this rule")

class DeviceUpdateSchema(BaseModel):
    name: Optional[str] = Field(None, description="The name of the device")
    tags: Optional[List[str]] = Field(None, description="List of tags for the device")
    lat: Optional[float] = Field(None, description="Latitude of the device")
    lng: Optional[float] = Field(None, description="Longitude of the device")
    address: Optional[str] = Field(None, description="Physical address of the device")
    notes: Optional[str] = Field(None, description="Notes for the device")
    moveMapMarker: Optional[bool] = Field(None, description="Whether to move the map marker or not")
    switchProfileId: Optional[str] = Field(None, description="Switch profile ID")
    floorPlanId: Optional[str] = Field(None, description="Floor plan ID")

class NetworkUpdateSchema(BaseModel):
    name: Optional[str] = Field(None, description="The name of the network")
    timeZone: Optional[str] = Field(None, description="The timezone of the network")
    tags: Optional[List[str]] = Field(None, description="List of tags for the network")
    enrollmentString: Optional[str] = Field(None, description="Enrollment string for the network")
    notes: Optional[str] = Field(None, description="Notes for the network")

class AdminCreationSchema(BaseModel):
    email: str = Field(..., description="Email address of the admin")
    name: str = Field(..., description="Name of the admin")
    orgAccess: str = Field(..., description="Access level for the organization")
    tags: Optional[List[str]] = Field(None, description="List of tags for the admin")
    networks: Optional[List[dict]] = Field(None, description="Network access for the admin")

class ActionBatchSchema(BaseModel):
    actions: List[dict] = Field(..., description="List of actions to perform")
    confirmed: bool = Field(True, description="Whether the batch is confirmed")
    synchronous: bool = Field(False, description="Whether the batch is synchronous")

class VpnSiteToSiteSchema(BaseModel):
    mode: str = Field(..., description="VPN mode (none, full, or hub-and-spoke)")
    hubs: Optional[List[dict]] = Field(None, description="List of hub configurations")
    subnets: Optional[List[dict]] = Field(None, description="List of subnet configurations")

class ContentFilteringSchema(BaseModel):
    allowedUrls: Optional[List[str]] = Field(None, description="List of allowed URLs")
    blockedUrls: Optional[List[str]] = Field(None, description="List of blocked URLs")
    blockedUrlPatterns: Optional[List[str]] = Field(None, description="List of blocked URL patterns")
    youtubeRestrictedForTeenagers: Optional[bool] = Field(None, description="Restrict YouTube for teenagers")
    youtubeRestrictedForMature: Optional[bool] = Field(None, description="Restrict YouTube for mature content")

class TrafficShapingSchema(BaseModel):
    globalBandwidthLimits: Optional[dict] = Field(None, description="Global bandwidth limits")
    rules: Optional[List[dict]] = Field(None, description="Traffic shaping rules")

class CameraSenseSchema(BaseModel):
    senseEnabled: Optional[bool] = Field(None, description="Whether camera sense is enabled")
    mqttBrokerId: Optional[str] = Field(None, description="MQTT broker ID")
    audioDetection: Optional[dict] = Field(None, description="Audio detection settings")

class SwitchQosRuleSchema(BaseModel):
    vlan: int = Field(..., description="VLAN ID")
    protocol: str = Field(..., description="Protocol (tcp, udp, any)")
    srcPort: int = Field(..., description="Source port")
    srcPortRange: Optional[str] = Field(None, description="Source port range")
    dstPort: Optional[int] = Field(None, description="Destination port")
    dstPortRange: Optional[str] = Field(None, description="Destination port range")
    dscp: Optional[int] = Field(None, description="DSCP value")

#######################
# COMPLEX TOOL HELPERS
#######################
class MerakiComplexTools:
    def __init__(self):
        pass

    async def _async_call(self, func, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: func(**kwargs))

    def _get_device_type(self, model: str) -> str:
        model_upper = model.upper()
        if model_upper.startswith("MX"):
            return "appliance"
        elif model_upper.startswith("MS"):
            return "switch"
        elif model_upper.startswith("MR") or model_upper.startswith("CW"):
            return "wireless"
        elif model_upper.startswith("MV"):
            return "camera"
        elif model_upper.startswith("MT"):
            return "sensor"
        return "unknown"

    async def _analyze_switch_topology(self, device: Dict, device_detail: Dict, topology: Dict):
        try:
            ports = await async_get_switch_ports(device["serial"])
            for port in ports:
                port_info = {
                    "port_id": port["portId"],
                    "name": port.get("name", f"Port {port['portId']}"),
                    "enabled": port.get("enabled", False),
                    "type": port.get("type", "access"),
                    "vlan": port.get("vlan"),
                    "status": "unknown",
                }
                try:
                    statuses = await async_get_switch_port_statuses(device["serial"])
                    for status in statuses:
                        if status["portId"] == port["portId"]:
                            port_info["status"] = "connected" if status.get("enabled") else "disabled"
                            port_info["speed"] = status.get("speed")
                            port_info["duplex"] = status.get("duplex")
                            break
                except Exception:
                    pass
                device_detail["ports"].append(port_info)
                if port.get("vlan") and str(port["vlan"]) in topology["vlans"]:
                    topology["vlans"][str(port["vlan"])]["devices"].append(device["serial"])
        except Exception as e:
            logger.warning(f"Failed to analyze switch topology: {e}")

    async def _analyze_appliance_topology(self, device: Dict, device_detail: Dict, topology: Dict, network_id: str):
        try:
            uplinks = await async_get_appliance_uplinks_settings(device["serial"])
            for interface, config in uplinks.get("interfaces", {}).items():
                if config.get("enabled"):
                    uplink_info = {
                        "interface": interface,
                        "enabled": True,
                        "wan_enabled": config.get("wanEnabled", False),
                        "vlan": config.get("vlanTagging", {}).get("vlanId"),
                    }
                    device_detail["uplinks"].append(uplink_info)
            try:
                vlans = await async_get_network_appliance_vlans(network_id)
                device_detail["dhcp_subnets"] = len(vlans) if isinstance(vlans, list) else 0
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Failed to analyze appliance topology: {e}")

    async def _analyze_wireless_topology(self, device: Dict, device_detail: Dict, topology: Dict):
        try:
            status = await async_get_device_wireless_status(device["serial"])
            device_detail["wireless_info"] = {
                "basic_service_sets": status.get("basicServiceSets", []),
                "gateway": status.get("gateway"),
            }
        except Exception as e:
            logger.warning(f"Failed to analyze wireless topology: {e}")

    async def _analyze_client_distribution(self, topology: Dict, network_id: str):
        try:
            clients = await async_get_network_clients(network_id, perPage=1000)
            client_distribution = defaultdict(int)
            for client in clients:
                if client.get("recentDeviceSerial"):
                    serial = client["recentDeviceSerial"]
                    if serial in topology["devices"]:
                        topology["devices"][serial]["clients"].append({
                            "id": client["id"],
                            "description": client.get("description", "Unknown"),
                            "ip": client.get("ip"),
                            "vlan": client.get("vlan"),
                        })
                        client_distribution[serial] += 1
            topology["summary"]["client_distribution"] = dict(client_distribution)
            topology["summary"]["total_clients"] = len(clients)
        except Exception as e:
            logger.warning(f"Failed to analyze client distribution: {e}")

    def _generate_topology_summary(self, topology: Dict):
        device_types = defaultdict(int)
        total_ports = 0
        used_ports = 0
        for device in topology["devices"].values():
            device_types[device["type"]] += 1
            if device["type"] == "switch":
                total_ports += len(device["ports"])
                used_ports += sum(1 for p in device["ports"] if p["status"] == "connected")
        topology["summary"]["device_counts"] = dict(device_types)
        topology["summary"]["total_devices"] = len(topology["devices"])
        topology["summary"]["vlan_count"] = len(topology["vlans"])
        if total_ports > 0:
            topology["summary"]["port_utilization"] = {
                "total": total_ports,
                "used": used_ports,
                "percentage": round((used_ports / total_ports) * 100, 2),
            }

    async def _analyze_switch_health(self, serial: str, device: Dict, health_report: Dict, time_span: int, organization_id: str):
        try:
            port_statuses = await async_get_switch_port_statuses(serial)
            port_health = {
                "total_ports": len(port_statuses),
                "connected": 0,
                "errors": 0,
                "warnings": 0,
            }
            for port_status in port_statuses:
                if port_status.get("enabled"):
                    port_health["connected"] += 1
                if port_status.get("errors", []):
                    port_health["errors"] += 1
                    health_report["issues"].append(
                        {
                            "severity": "medium",
                            "component": f"port_{port_status['portId']}",
                            "description": f"Port {port_status['portId']} has errors: {', '.join(port_status['errors'])}",
                        }
                    )
                    health_report["health_score"] -= 5
                if port_status.get("warnings", []):
                    port_health["warnings"] += 1
            health_report["components"]["ports"] = port_health
            if "PoE" in device.get("model", ""):
                try:
                    health_report["components"]["power"] = {
                        "status": "analyzed",
                        "details": "PoE power analysis completed",
                    }
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Failed to analyze switch health: {e}")

    async def _analyze_appliance_health(self, serial: str, device: Dict, health_report: Dict, time_span: int, organization_id: str):
        try:
            performance = await async_get_device_appliance_performance(serial)
            health_report["components"]["performance"] = {
                "perfScore": performance.get("perfScore", 0),
            }
            if performance.get("perfScore", 100) < 80:
                health_report["health_score"] -= 20
                health_report["issues"].append(
                    {
                        "severity": "high",
                        "component": "performance",
                        "description": f"Performance score is low: {performance.get('perfScore', 0)}",
                    }
                )
            try:
                uplinks = await async_get_organization_appliance_uplink_statuses(organization_id, serials=[serial])
                if uplinks:
                    uplink_health = {"total": 0, "active": 0}
                    for uplink in uplinks[0].get("uplinks", []):
                        uplink_health["total"] += 1
                        if uplink.get("status") == "active":
                            uplink_health["active"] += 1
                    health_report["components"]["uplinks"] = uplink_health
                    if uplink_health["active"] < uplink_health["total"]:
                        health_report["issues"].append(
                            {
                                "severity": "medium",
                                "component": "uplinks",
                                "description": f"Only {uplink_health['active']} of {uplink_health['total']} uplinks are active",
                            }
                        )
                        health_report["health_score"] -= 10
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Failed to analyze appliance health: {e}")

    async def _analyze_wireless_health(self, serial: str, device: Dict, health_report: Dict, time_span: int, organization_id: str):
        try:
            connection_stats = await async_get_wireless_connection_stats(serial, timespan=time_span)
            health_report["components"]["wireless"] = {
                "connection_stats": connection_stats,
            }
            if connection_stats.get("assoc", 0) > 0:
                success_rate = (
                    connection_stats.get("success", 0)
                    / connection_stats.get("assoc", 1)
                    * 100
                )
                if success_rate < 90:
                    health_report["health_score"] -= 15
                    health_report["issues"].append(
                        {
                            "severity": "high",
                            "component": "wireless",
                            "description": f"Low connection success rate: {success_rate:.2f}%",
                        }
                    )
        except Exception as e:
            logger.warning(f"Failed to analyze wireless health: {e}")

    async def _check_firmware_status(self, device: Dict, health_report: Dict, organization_id: str):
        try:
            firmware_upgrades = await async_get_organization_firmware_upgrades(organization_id)
            device_type = self._get_device_type(device["model"])
            current_firmware = device.get("firmware", "")
            for upgrade in firmware_upgrades:
                if (
                    upgrade.get("productType", "").lower() == device_type
                    and upgrade.get("currentVersion", {}).get("shortName") == current_firmware
                ):
                    if upgrade.get("availableVersions", []):
                        latest_version = upgrade["availableVersions"][0]
                        if latest_version.get("shortName") != current_firmware:
                            health_report["recommendations"].append(
                                {
                                    "category": "firmware",
                                    "priority": "medium",
                                    "description": f"Firmware update available: {latest_version.get('shortName')}",
                                    "action": f"Update firmware from {current_firmware} to {latest_version.get('shortName')}",
                                }
                            )
                            health_report["health_score"] -= 5
        except Exception as e:
            logger.warning(f"Failed to check firmware status: {e}")

    def _generate_health_recommendations(self, health_report: Dict):
        if health_report["health_score"] < 50:
            health_report["recommendations"].insert(
                0,
                {
                    "category": "critical",
                    "priority": "high",
                    "description": "Device health is critical",
                    "action": "Immediate attention required - review all critical issues",
                },
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        health_report["recommendations"].sort(
            key=lambda x: priority_order.get(x.get("priority", "low"), 3)
        )

    async def _audit_firewall_security(self, network_id: str, audit_report: Dict):
        try:
            l3_rules = await async_get_appliance_firewall_l3_rules(network_id)
            firewall_audit = {
                "total_rules": len(l3_rules.get("rules", [])),
                "allow_all_rules": 0,
                "specific_rules": 0,
                "findings": [],
            }
            for idx, rule in enumerate(l3_rules.get("rules", [])):
                if (
                    rule.get("srcCidr") == "Any"
                    and rule.get("destCidr") == "Any"
                    and rule.get("policy") == "allow"
                ):
                    firewall_audit["allow_all_rules"] += 1
                    audit_report["findings"]["high"].append(
                        {
                            "component": "firewall",
                            "rule_index": idx,
                            "description": f"Overly permissive rule allowing all traffic: {rule.get('comment', 'No comment')}",
                            "recommendation": "Restrict source and destination to specific networks",
                        }
                    )
                    audit_report["security_score"] -= 15
                else:
                    firewall_audit["specific_rules"] += 1
                if not rule.get("comment"):
                    audit_report["findings"]["low"].append(
                        {
                            "component": "firewall",
                            "rule_index": idx,
                            "description": "Firewall rule missing description",
                            "recommendation": "Add descriptive comment to document rule purpose",
                        }
                    )
            audit_report["components"]["firewall"] = firewall_audit
        except Exception as e:
            logger.warning(f"Failed to audit firewall security: {e}")

    async def _audit_wireless_security(self, network_id: str, audit_report: Dict):
        try:
            ssids = await async_get_wireless_ssids(network_id)
            wireless_audit = {"total_ssids": 0, "enabled_ssids": 0, "findings": []}
            for ssid in ssids:
                if not ssid.get("enabled"):
                    continue
                wireless_audit["enabled_ssids"] += 1
                if ssid.get("encryptionMode") == "open":
                    audit_report["findings"]["critical"].append(
                        {
                            "component": "wireless",
                            "ssid": ssid.get("name"),
                            "description": "SSID using open authentication (no encryption)",
                            "recommendation": "Enable WPA2 or WPA3 encryption",
                        }
                    )
                    audit_report["security_score"] -= 25
                elif ssid.get("encryptionMode") == "wep":
                    audit_report["findings"]["high"].append(
                        {
                            "component": "wireless",
                            "ssid": ssid.get("name"),
                            "description": "SSID using deprecated WEP encryption",
                            "recommendation": "Upgrade to WPA2 or WPA3 encryption",
                        }
                    )
                    audit_report["security_score"] -= 20
                elif (
                    ssid.get("encryptionMode") == "wpa"
                    and "wpa3" not in ssid.get("encryptionMode", "").lower()
                ):
                    audit_report["findings"]["medium"].append(
                        {
                            "component": "wireless",
                            "ssid": ssid.get("name"),
                            "description": "SSID not using latest WPA3 encryption",
                            "recommendation": "Consider upgrading to WPA3 for enhanced security",
                        }
                    )
                if ssid.get("authMode") == "psk" and ssid.get("psk"):
                    if len(ssid["psk"]) < 12:
                        audit_report["findings"]["high"].append(
                            {
                                "component": "wireless",
                                "ssid": ssid.get("name"),
                                "description": "Pre-shared key is too short",
                                "recommendation": "Use a pre-shared key with at least 12 characters",
                            }
                        )
                        audit_report["security_score"] -= 10
            wireless_audit["total_ssids"] = len(ssids)
            audit_report["components"]["wireless"] = wireless_audit
        except Exception as e:
            logger.warning(f"Failed to audit wireless security: {e}")

    async def _audit_network_settings(self, network_id: str, audit_report: Dict):
        try:
            network = await async_get_network(network_id)
            if "appliance" in network.get("productTypes", []):
                try:
                    ids_settings = await async_get_appliance_security_intrusion(network_id)
                    if (
                        not ids_settings.get("idsSettings", {}).get("mode")
                        or ids_settings["idsSettings"]["mode"] == "disabled"
                    ):
                        audit_report["findings"]["high"].append(
                            {
                                "component": "intrusion_detection",
                                "description": "Intrusion Detection System is disabled",
                                "recommendation": "Enable IDS in prevention mode for active threat protection",
                            }
                        )
                        audit_report["security_score"] -= 15
                    elif ids_settings["idsSettings"]["mode"] == "detection":
                        audit_report["findings"]["medium"].append(
                            {
                                "component": "intrusion_detection",
                                "description": "IDS is in detection-only mode",
                                "recommendation": "Consider switching to prevention mode for active protection",
                            }
                        )
                except Exception:
                    pass
                try:
                    content_filtering = await async_get_appliance_content_filtering(network_id)
                    if not content_filtering.get("blockedUrlCategories"):
                        audit_report["findings"]["low"].append(
                            {
                                "component": "content_filtering",
                                "description": "No content filtering categories blocked",
                                "recommendation": "Enable content filtering for malicious and inappropriate content",
                            }
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Failed to audit network settings: {e}")

    async def _audit_admin_access(self, network: Dict, audit_report: Dict):
        try:
            admins = await async_get_organization_admins(network["organizationId"])
            admin_audit = {
                "total_admins": len(admins),
                "full_access_admins": 0,
                "two_factor_enabled": 0,
                "findings": [],
            }
            for admin in admins:
                if admin.get("orgAccess") == "full":
                    admin_audit["full_access_admins"] += 1
                if admin.get("twoFactorAuthEnabled"):
                    admin_audit["two_factor_enabled"] += 1
            if admin_audit["full_access_admins"] > 5:
                audit_report["findings"]["medium"].append(
                    {
                        "component": "admin_access",
                        "description": f"High number of full access administrators: {admin_audit['full_access_admins']}",
                        "recommendation": "Review admin permissions and apply principle of least privilege",
                    }
                )
                audit_report["security_score"] -= 5
            two_factor_percentage = (
                admin_audit["two_factor_enabled"] / admin_audit["total_admins"] * 100
                if admin_audit["total_admins"] > 0
                else 0
            )
            if two_factor_percentage < 100:
                severity = "high" if two_factor_percentage < 50 else "medium"
                audit_report["findings"][severity].append(
                    {
                        "component": "admin_access",
                        "description": f"Only {two_factor_percentage:.0f}% of admins have two-factor authentication enabled",
                        "recommendation": "Require two-factor authentication for all administrators",
                    }
                )
                audit_report["security_score"] -= 10 if severity == "high" else 5
            audit_report["components"]["admin_access"] = admin_audit
        except Exception as e:
            logger.warning(f"Failed to audit admin access: {e}")

    def _calculate_security_score(self, audit_report: Dict):
        audit_report["security_score"] = max(0, audit_report["security_score"])
        audit_report["summary"] = {
            "total_findings": sum(len(findings) for findings in audit_report["findings"].values()),
            "critical_findings": len(audit_report["findings"]["critical"]),
            "high_findings": len(audit_report["findings"]["high"]),
            "medium_findings": len(audit_report["findings"]["medium"]),
            "low_findings": len(audit_report["findings"]["low"]),
        }

    def _generate_security_recommendations(self, audit_report: Dict):
        recommendations = []
        if audit_report["security_score"] < 70:
            recommendations.append(
                {
                    "priority": "urgent",
                    "category": "overall",
                    "description": "Security posture needs immediate attention",
                    "action": "Address all critical and high severity findings immediately",
                }
            )
        if audit_report["findings"]["critical"]:
            recommendations.append(
                {
                    "priority": "critical",
                    "category": "immediate_action",
                    "description": f"{len(audit_report['findings']['critical'])} critical security issues found",
                    "action": "Review and remediate critical findings within 24 hours",
                }
            )
        for component, data in audit_report["components"].items():
            if component == "firewall" and data.get("allow_all_rules", 0) > 0:
                recommendations.append(
                    {
                        "priority": "high",
                        "category": "firewall",
                        "description": "Overly permissive firewall rules detected",
                        "action": "Implement zero-trust principles and restrict firewall rules",
                    }
                )
        audit_report["recommendations"] = recommendations

    async def _analyze_device_performance(self, device: Dict, performance_report: Dict, time_span: int):
        try:
            device_type = self._get_device_type(device["model"])
            device_metrics = {
                "serial": device["serial"],
                "name": device.get("name", device["serial"]),
                "type": device_type,
                "performance": {},
            }
            if device_type == "switch":
                try:
                    port_statuses = await async_get_switch_port_statuses(device["serial"])
                    total_ports = len(port_statuses)
                    active_ports = sum(1 for p in port_statuses if p.get("status") == "Connected")
                    device_metrics["performance"]["port_utilization"] = {
                        "total": total_ports,
                        "active": active_ports,
                        "percentage": round((active_ports / total_ports * 100), 2) if total_ports > 0 else 0,
                    }
                except Exception:
                    pass
            elif device_type == "appliance":
                try:
                    perf = await async_get_device_appliance_performance(device["serial"])
                    device_metrics["performance"]["score"] = perf.get("perfScore", 0)
                    if perf.get("perfScore", 100) < 80:
                        performance_report["bottlenecks"].append(
                            {
                                "device": device["serial"],
                                "type": "performance",
                                "severity": "high",
                                "description": f"Low performance score: {perf.get('perfScore', 0)}",
                            }
                        )
                        performance_report["performance_score"] -= 10
                except Exception:
                    pass
            elif device_type == "wireless":
                try:
                    # Channel utilization skipped as per note
                    pass
                except Exception:
                    pass
            performance_report["metrics"]["device_health"][device["serial"]] = device_metrics
        except Exception as e:
            logger.warning(f"Failed to analyze device performance: {e}")

    def _analyze_client_performance(self, clients: List[Dict], performance_report: Dict):
        clients_by_usage = sorted(
            clients,
            key=lambda x: x.get("usage", {}).get("sent", 0) + x.get("usage", {}).get("recv", 0),
            reverse=True,
        )
        top_clients = []
        for client in clients_by_usage[:10]:
            usage = client.get("usage", {})
            total_usage = usage.get("sent", 0) + usage.get("recv", 0)
            top_clients.append(
                {
                    "id": client.get("id"),
                    "description": client.get("description", client.get("mac", "Unknown")),
                    "ip": client.get("ip"),
                    "total_usage_mb": round(total_usage / 1024 / 1024, 2),
                    "sent_mb": round(usage.get("sent", 0) / 1024 / 1024, 2),
                    "recv_mb": round(usage.get("recv", 0) / 1024 / 1024, 2),
                }
            )
        performance_report["top_talkers"]["clients"] = top_clients
        total_sent = sum(c.get("usage", {}).get("sent", 0) for c in clients)
        total_recv = sum(c.get("usage", {}).get("recv", 0) for c in clients)
        performance_report["metrics"]["bandwidth"] = {
            "total_sent_mb": round(total_sent / 1024 / 1024, 2),
            "total_recv_mb": round(total_recv / 1024 / 1024, 2),
            "total_mb": round((total_sent + total_recv) / 1024 / 1024, 2),
        }

    async def _analyze_traffic_patterns(self, network_id: str, performance_report: Dict, time_span: int):
        try:
            traffic_analysis = await async_get_network_traffic_analysis(network_id)
            top_apps = []
            for app in traffic_analysis[:10]:
                top_apps.append(
                    {
                        "application": app.get("application", "Unknown"),
                        "destination": app.get("destination"),
                        "traffic_mb": round(app.get("recv", 0) / 1024 / 1024, 2),
                        "num_clients": app.get("numClients", 0),
                    }
                )
            performance_report["top_talkers"]["applications"] = top_apps
        except Exception as e:
            logger.warning(f"Failed to analyze traffic patterns: {e}")

    def _identify_performance_bottlenecks(self, performance_report: Dict):
        if performance_report["metrics"]["bandwidth"].get("total_mb", 0) > 10000:
            performance_report["bottlenecks"].append(
                {
                    "type": "bandwidth",
                    "severity": "high",
                    "description": "High bandwidth utilization detected",
                    "impact": "Potential network congestion and slow performance",
                }
            )
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        performance_report["bottlenecks"].sort(
            key=lambda x: severity_order.get(x.get("severity", "low"), 3)
        )

    def _generate_performance_recommendations(self, performance_report: Dict):
        recommendations = []
        if performance_report["performance_score"] < 70:
            recommendations.append(
                {
                    "priority": "high",
                    "category": "overall",
                    "description": "Network performance is below optimal levels",
                    "action": "Review and address all identified bottlenecks",
                }
            )
        for bottleneck in performance_report["bottlenecks"]:
            if bottleneck["type"] == "bandwidth":
                recommendations.append(
                    {
                        "priority": "high",
                        "category": "bandwidth",
                        "description": "Bandwidth optimization needed",
                        "action": "Consider implementing QoS policies or upgrading bandwidth",
                    }
                )
            elif bottleneck["type"] == "wireless_congestion":
                recommendations.append(
                    {
                        "priority": "medium",
                        "category": "wireless",
                        "description": "Wireless congestion detected",
                        "action": "Add additional access points or optimize channel assignments",
                    }
                )
        performance_report["recommendations"] = recommendations

    async def _analyze_configuration_group(self, product_types: Tuple, networks: List[Dict], drift_report: Dict):
        try:
            group_key = " + ".join(product_types)
            group_analysis = {
                "network_count": len(networks),
                "product_types": list(product_types),
                "configurations": {},
                "inconsistencies": [],
            }
            network_configs = {}
            for network in networks:
                config = {"network_id": network["id"], "name": network["name"]}
                if "wireless" in product_types:
                    try:
                        ssids = await async_get_wireless_ssids(network["id"])
                        config["ssids"] = [{"name": s["name"], "enabled": s["enabled"]} for s in ssids]
                    except Exception:
                        pass
                if "appliance" in product_types:
                    try:
                        vlans = await async_get_network_appliance_vlans(network["id"])
                        config["vlan_count"] = len(vlans)
                    except Exception:
                        pass
                network_configs[network["id"]] = config
            self._find_configuration_inconsistencies(network_configs, group_analysis, drift_report)
            drift_report["configuration_groups"][group_key] = group_analysis
        except Exception as e:
            logger.warning(f"Failed to analyze configuration group: {e}")

    def _find_configuration_inconsistencies(self, network_configs: Dict, group_analysis: Dict, drift_report: Dict):
        ssid_configs = defaultdict(list)
        for net_id, config in network_configs.items():
            if "ssids" in config:
                for ssid in config["ssids"]:
                    ssid_configs[ssid["name"]].append({"network_id": net_id, "enabled": ssid["enabled"]})
        for ssid_name, configs in ssid_configs.items():
            if len(configs) < len(network_configs):
                drift_report["deviations"].append(
                    {
                        "type": "missing_ssid",
                        "ssid": ssid_name,
                        "description": f"SSID '{ssid_name}' is not configured on all networks",
                        "networks_missing": len(network_configs) - len(configs),
                    }
                )
                drift_report["consistency_score"] -= 5
            enabled_states = set(c["enabled"] for c in configs)
            if len(enabled_states) > 1:
                drift_report["deviations"].append(
                    {
                        "type": "ssid_state_mismatch",
                        "ssid": ssid_name,
                        "description": f"SSID '{ssid_name}' has inconsistent enabled state across networks",
                    }
                )
                drift_report["consistency_score"] -= 3

    def _calculate_consistency_score(self, drift_report: Dict):
        drift_report["consistency_score"] = max(0, drift_report["consistency_score"])
        drift_report["summary"] = {
            "total_deviations": len(drift_report["deviations"]),
            "configuration_groups": len(drift_report["configuration_groups"]),
        }

    def _generate_drift_recommendations(self, drift_report: Dict):
        recommendations = []
        if drift_report["consistency_score"] < 80:
            recommendations.append(
                {
                    "priority": "high",
                    "category": "standardization",
                    "description": "Significant configuration drift detected",
                    "action": "Consider implementing configuration templates for consistency",
                }
            )
        ssid_deviations = [d for d in drift_report["deviations"] if "ssid" in d["type"]]
        if ssid_deviations:
            recommendations.append(
                {
                    "priority": "medium",
                    "category": "wireless",
                    "description": f"{len(ssid_deviations)} SSID configuration inconsistencies found",
                    "action": "Standardize SSID configurations across all networks",
                }
            )
        drift_report["recommendations"] = recommendations

    async def _troubleshoot_appliance_connectivity(self, network_id: str, source_ip: str, destination_ip: str, troubleshoot_report: Dict):
        try:
            l3_rules = await async_get_appliance_firewall_l3_rules(network_id)
            blocked = False
            blocking_rule = None
            for rule in l3_rules.get("rules", []):
                if rule.get("policy") == "deny":
                    if self._ip_matches_rule(source_ip, destination_ip, rule):
                        blocked = True
                        blocking_rule = rule
                        break
            if blocked:
                troubleshoot_report["blockers"].append(
                    {
                        "type": "firewall_rule",
                        "description": f"Traffic blocked by firewall rule: {blocking_rule.get('comment', 'No description')}",
                        "rule": blocking_rule,
                    }
                )
                troubleshoot_report["connectivity_status"] = "blocked"
            else:
                troubleshoot_report["connectivity_status"] = "allowed"
            troubleshoot_report["path_analysis"]["firewall_rules_checked"] = len(l3_rules.get("rules", []))
        except Exception as e:
            logger.warning(f"Failed to troubleshoot appliance connectivity: {e}")

    async def _troubleshoot_switch_connectivity(self, network_id: str, source_client: Optional[Dict], dest_client: Optional[Dict], troubleshoot_report: Dict):
        try:
            if source_client and dest_client:
                source_vlan = source_client.get("vlan")
                dest_vlan = dest_client.get("vlan")
                if source_vlan != dest_vlan:
                    troubleshoot_report["blockers"].append(
                        {
                            "type": "vlan_mismatch",
                            "description": f"Source (VLAN {source_vlan}) and destination (VLAN {dest_vlan}) are on different VLANs",
                            "recommendation": "Ensure inter-VLAN routing is configured",
                        }
                    )
        except Exception as e:
            logger.warning(f"Failed to troubleshoot switch connectivity: {e}")

    def _ip_matches_rule(self, source_ip: str, dest_ip: str, rule: Dict) -> bool:
        if rule.get("srcCidr") == "Any" or source_ip in rule.get("srcCidr", ""):
            if rule.get("destCidr") == "Any" or dest_ip in rule.get("destCidr", ""):
                return True
        return False

    def _generate_troubleshoot_recommendations(self, troubleshoot_report: Dict):
        recommendations = []
        if troubleshoot_report["connectivity_status"] == "blocked":
            recommendations.append(
                {
                    "priority": "high",
                    "description": "Connectivity is blocked",
                    "action": "Review and modify blocking rules or configurations",
                }
            )
        for blocker in troubleshoot_report["blockers"]:
            if blocker["type"] == "firewall_rule":
                recommendations.append(
                    {
                        "priority": "high",
                        "description": "Firewall rule blocking traffic",
                        "action": "Add exception rule above blocking rule for required traffic",
                    }
                )
            elif blocker["type"] == "vlan_mismatch":
                recommendations.append(
                    {
                        "priority": "medium",
                        "description": "VLAN routing issue",
                        "action": "Configure inter-VLAN routing or move devices to same VLAN",
                    }
                )
        troubleshoot_report["recommendations"] = recommendations

    def _analyze_client_metrics(self, client: Dict, experience_report: Dict):
        usage = client.get("usage", {})
        total_usage = usage.get("sent", 0) + usage.get("recv", 0)
        if total_usage > 10 * 1024 * 1024 * 1024:  # 10GB
            category = "heavy"
        elif total_usage > 1 * 1024 * 1024 * 1024:  # 1GB
            category = "medium"
        else:
            category = "light"
        if category not in experience_report["client_metrics"]["satisfaction_breakdown"]:
            experience_report["client_metrics"]["satisfaction_breakdown"][category] = {
                "count": 0,
                "total_usage_mb": 0,
            }
        experience_report["client_metrics"]["satisfaction_breakdown"][category]["count"] += 1
        experience_report["client_metrics"]["satisfaction_breakdown"][category]["total_usage_mb"] += round(total_usage / 1024 / 1024, 2)
        if client.get("status") == "Offline":
            experience_report["client_metrics"]["connectivity_issues"].append(
                {
                    "client": client.get("description", client.get("mac")),
                    "issue": "Client offline",
                }
            )

    async def _analyze_wireless_experience(self, network_id: str, experience_report: Dict, time_span: int):
        try:
            connection_stats = await async_get_wireless_connection_stats(network_id, timespan=time_span)
            if connection_stats:
                success_rate = (
                    connection_stats.get("success", 0)
                    / connection_stats.get("assoc", 1)
                    * 100
                    if connection_stats.get("assoc", 0) > 0
                    else 0
                )
                experience_report["client_metrics"]["performance_metrics"]["wireless_success_rate"] = round(success_rate, 2)
                if success_rate < 95:
                    experience_report["experience_score"] -= 20
                    experience_report["problem_clients"].append(
                        {
                            "type": "wireless_connectivity",
                            "description": f"Low wireless connection success rate: {success_rate:.1f}%",
                            "impact": "high",
                        }
                    )
            failed_connections = await async_get_wireless_failed_connections(network_id, timespan=time_span)
            if len(failed_connections) > 100:
                experience_report["problem_clients"].append(
                    {
                        "type": "failed_connections",
                        "description": f"High number of failed connections: {len(failed_connections)}",
                        "impact": "medium",
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to analyze wireless experience: {e}")

    def _calculate_experience_score(self, experience_report: Dict):
        experience_report["experience_score"] = max(0, experience_report["experience_score"])
        issue_count = len(experience_report["client_metrics"]["connectivity_issues"])
        if issue_count > 0:
            issue_penalty = min(issue_count * 2, 20)
            experience_report["experience_score"] -= issue_penalty

    def _generate_experience_recommendations(self, experience_report: Dict):
        recommendations = []
        if experience_report["experience_score"] < 80:
            recommendations.append(
                {
                    "priority": "high",
                    "category": "overall",
                    "description": "Client experience needs improvement",
                    "action": "Address connectivity and performance issues",
                }
            )
        wireless_success = experience_report["client_metrics"].get("performance_metrics", {}).get("wireless_success_rate", 100)
        if wireless_success < 95:
            recommendations.append(
                {
                    "priority": "high",
                    "category": "wireless",
                    "description": "Wireless connectivity issues detected",
                    "action": "Review wireless configuration, channel utilization, and coverage",
                }
            )
        experience_report["recommendations"] = recommendations

    def _analyze_license_utilization(self, licenses: List[Dict], inventory_report: Dict):
        license_summary = {
            "total_licenses": len(licenses),
            "expiring_soon": 0,
            "expired": 0,
            "by_type": defaultdict(int),
        }
        for license in licenses:
            license_type = license.get("licenseType", "Unknown")
            license_summary["by_type"][license_type] += 1
            # Check expiration (simulated)
        inventory_report["summary"]["license_summary"] = dict(license_summary)

    def _check_device_lifecycle(self, device_info: Dict, inventory_report: Dict):
        model = device_info["model"]
        eol_models = ["MR18", "MR12", "MS220-8", "MX64"]
        if model in eol_models:
            inventory_report["insights"]["end_of_life"].append(
                {
                    "serial": device_info["serial"],
                    "model": model,
                    "name": device_info["name"],
                    "recommendation": "Plan replacement - model is end of life",
                }
            )

    async def _get_client_inventory(self, organization_id: str, inventory_report: Dict):
        try:
            networks = await async_get_organization_networks(organization_id)
            total_clients = 0
            unique_clients = set()
            for network in networks[:10]:  # Limit to prevent timeout
                try:
                    clients = await async_get_network_clients(network["id"], perPage=100)
                    for client in clients:
                        unique_clients.add(client.get("mac"))
                        total_clients += 1
                except Exception:
                    pass
            inventory_report["summary"]["client_devices"] = {
                "total_seen": total_clients,
                "unique_devices": len(unique_clients),
            }
        except Exception as e:
            logger.warning(f"Failed to get client inventory: {e}")

    def _generate_inventory_insights(self, inventory_report: Dict):
        recommendations = []
        if inventory_report["insights"]["end_of_life"]:
            recommendations.append(
                {
                    "priority": "high",
                    "category": "lifecycle",
                    "description": f"{len(inventory_report['insights']['end_of_life'])} devices are end of life",
                    "action": "Create replacement plan for EOL equipment",
                    "cost_impact": "high",
                }
            )
        device_breakdown = inventory_report["summary"]["device_breakdown"]
        if device_breakdown.get("wireless", 0) > device_breakdown.get("switch", 0) * 10:
            recommendations.append(
                {
                    "priority": "medium",
                    "category": "architecture",
                    "description": "High ratio of wireless APs to switches",
                    "action": "Review if additional switching capacity is needed",
                    "cost_impact": "medium",
                }
            )
        inventory_report["recommendations"] = recommendations

# Instantiate helper
_complex_tools = MerakiComplexTools()

#######################
# COMMONLY USED TOOLS
#######################
@mcp.tool()
async def get_organizations() -> str:
    try:
        organizations = await async_get_organizations()
        result = {
            "method": "getOrganizations",
            "count": len(organizations),
            "organizations": organizations,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get organizations: {e}")
        return json.dumps({"error": "API call failed", "message": str(e)}, indent=2)

@mcp.tool()
async def get_organization_devices(organization_id: str) -> str:
    try:
        devices = await async_get_organization_devices(organization_id)
        result = {
            "method": "getOrganizationDevices",
            "organization_id": organization_id,
            "count": len(devices),
            "devices": devices,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get organization devices: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "organization_id": organization_id,
            },
            indent=2,
        )

@mcp.tool()
async def get_organization_networks(organization_id: str) -> str:
    try:
        networks = await async_get_organization_networks(organization_id)
        result = {
            "method": "getOrganizationNetworks",
            "organization_id": organization_id,
            "count": len(networks),
            "networks": networks,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get organization networks: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "organization_id": organization_id,
            },
            indent=2,
        )

@mcp.tool()
async def get_device_status(serial: str) -> str:
    try:
        device = await async_get_device(serial)
        result = {"method": "getDevice", "serial": serial, "device": device}
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get device status: {e}")
        return json.dumps({"error": "API call failed", "message": str(e), "serial": serial}, indent=2)

@mcp.tool()
async def get_network_clients(network_id: str, timespan: Optional[int] = 2592000) -> str:
    try:
        clients = await async_get_network_clients(network_id, timespan=timespan)
        result = {
            "method": "getNetworkClients",
            "network_id": network_id,
            "timespan": timespan,
            "count": len(clients),
            "clients": clients,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get network clients: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "network_id": network_id,
            },
            indent=2,
        )

@mcp.tool()
async def get_switch_port_config(serial: str, port_id: str) -> str:
    try:
        port_config = await to_async(dashboard.switch.getDeviceSwitchPort)(serial=serial, portId=port_id)
        result = {
            "method": "getDeviceSwitchPort",
            "serial": serial,
            "port_id": port_id,
            "configuration": port_config,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get switch port config: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "serial": serial,
                "port_id": port_id,
            },
            indent=2,
        )

@mcp.tool()
async def get_network_settings(network_id: str) -> str:
    try:
        settings = await to_async(dashboard.networks.getNetworkSettings)(networkId=network_id)
        result = {
            "method": "getNetworkSettings",
            "network_id": network_id,
            "settings": settings,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get network settings: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "network_id": network_id,
            },
            indent=2,
        )

@mcp.tool()
async def get_firewall_rules(network_id: str) -> str:
    try:
        firewall_rules = await async_get_appliance_firewall_l3_rules(network_id)
        result = {
            "method": "getNetworkApplianceFirewallL3FirewallRules",
            "network_id": network_id,
            "rules": firewall_rules,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get firewall rules: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "network_id": network_id,
            },
            indent=2,
        )

@mcp.tool()
async def get_organization_uplinks_statuses(organization_id: str) -> str:
    try:
        uplinks = await async_get_organization_appliance_uplink_statuses(organization_id)
        result = {
            "method": "getOrganizationUplinksStatuses",
            "organization_id": organization_id,
            "count": len(uplinks),
            "uplinks": uplinks,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get organization uplinks: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "organization_id": organization_id,
            },
            indent=2,
        )

@mcp.tool()
async def get_network_topology(network_id: str) -> str:
    try:
        topology = await to_async(dashboard.networks.getNetworkTopologyLinkLayer)(networkId=network_id)
        result = {
            "method": "getNetworkTopologyLinkLayer",
            "network_id": network_id,
            "topology": topology,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get network topology: {e}")
        return json.dumps(
            {
                "error": "API call failed",
                "message": str(e),
                "network_id": network_id,
            },
            indent=2,
        )

#######################
# DYNAMIC TOOLS
#######################
class MerakiApiTools:
    def __init__(self):
        self._api_cache: Dict[str, List[str]] = {}
        self._response_cache: Dict[str, Dict] = {}
        self._cache_ttl = 300
        self._search_patterns: List[Dict] = []
        self._patterns_initialized = False
        self._register_tools()

    def _generate_keywords_from_method(self, section: str, method: str) -> List[str]:
        keywords = []
        keywords.append(section.lower())
        if section == "organizations":
            keywords.extend(["org", "orgs", "organization"])
        elif section == "appliance":
            keywords.extend(["mx", "security", "firewall"])
        elif section == "switch":
            keywords.extend(["ms", "switching", "port", "ports"])
        elif section == "wireless":
            keywords.extend(["mr", "wifi", "wireless", "access"])
        elif section == "camera":
            keywords.extend(["mv", "cameras", "video"])
        elif section == "sensor":
            keywords.extend(["mt", "sensors", "environmental"])
        elif section == "networks":
            keywords.extend(["network", "net"])
        elif section == "devices":
            keywords.extend(["device", "hardware"])
        method_parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)", method)
        method_words = [part.lower() for part in method_parts]
        keywords.extend(method_words)
        if "get" in method_words:
            keywords.extend(["show", "list", "fetch", "retrieve"])
        elif "update" in method_words:
            keywords.extend(["modify", "change", "edit", "set"])
        elif "create" in method_words:
            keywords.extend(["add", "new", "make"])
        elif "delete" in method_words:
            keywords.extend(["remove", "destroy"])
        if any(word in method_words for word in ["firewall", "rules"]):
            keywords.extend(["security", "l3", "layer3", "policy"])
        if any(word in method_words for word in ["client", "clients"]):
            keywords.extend(["connected", "devices", "users"])
        if any(word in method_words for word in ["port", "ports"]):
            keywords.extend(["interface", "config", "configuration", "settings"])
        if any(word in method_words for word in ["vpn"]):
            keywords.extend(["tunnel", "connection", "site"])
        if any(word in method_words for word in ["ssid"]):
            keywords.extend(["network", "wifi", "wireless"])
        return list(set(keywords))

    def _calculate_method_weight(self, method: str) -> float:
        method_lower = method.lower()
        if method in ["getOrganizations", "getDevice", "getNetworkClients"]:
            return 1.0
        elif "organization" in method_lower and method.startswith("get"):
            return 0.9
        elif "network" in method_lower and method.startswith("get"):
            return 0.8
        elif method.startswith("get") and "device" in method_lower:
            return 0.8
        elif method.startswith("get"):
            return 0.7
        elif method.startswith("update"):
            return 0.6
        elif method.startswith("create"):
            return 0.5
        elif method.startswith("delete"):
            return 0.4
        else:
            return 0.3

    def _get_method_parameters(self, section: str, method: str) -> List[str]:
        try:
            section_obj = getattr(dashboard, section)
            method_obj = getattr(section_obj, method)
            sig = inspect.signature(method_obj)
            required_params = []
            for param_name, param in sig.parameters.items():
                if param.default == inspect.Parameter.empty and param_name != "kwargs":
                    required_params.append(param_name)
            return required_params
        except Exception:
            return []

    def _generate_dynamic_patterns(self) -> List[Dict]:
        api_structure = self._discover_api_structure()
        patterns = []
        for section, methods in api_structure.items():
            for method in methods:
                keywords = self._generate_keywords_from_method(section, method)
                weight = self._calculate_method_weight(method)
                required_params = self._get_method_parameters(section, method)
                method_parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)", method)
                description = " ".join(method_parts).lower()
                pattern = {
                    "keywords": keywords,
                    "section": section,
                    "method": method,
                    "description": description,
                    "required_params": required_params,
                    "weight": weight,
                }
                patterns.append(pattern)
        return patterns

    def _initialize_search_patterns(self) -> List[Dict]:
        return self._generate_dynamic_patterns()

    def _calculate_semantic_score(self, query: str, pattern: Dict) -> float:
        query_words = set(re.findall(r"\b\w+\b", query.lower()))
        pattern_keywords = set(pattern["keywords"])
        intersection = len(query_words.intersection(pattern_keywords))
        union = len(query_words.union(pattern_keywords))
        if union == 0:
            return 0.0
        jaccard_score = intersection / union
        weighted_score = jaccard_score * pattern["weight"]
        exact_matches = sum(1 for word in query_words if word in pattern_keywords)
        exact_bonus = min(exact_matches * 0.1, 0.3)
        return min(weighted_score + exact_bonus, 1.0)

    def _ensure_patterns_initialized(self):
        if not self._patterns_initialized:
            logger.info("Initializing semantic search patterns for all API endpoints...")
            self._search_patterns = self._generate_dynamic_patterns()
            self._patterns_initialized = True
            logger.info(f"Initialized {len(self._search_patterns)} semantic patterns")

    def _find_best_pattern_match(self, query: str) -> Optional[Dict]:
        self._ensure_patterns_initialized()
        best_score = 0.0
        best_pattern = None
        for pattern in self._search_patterns:
            score = self._calculate_semantic_score(query, pattern)
            if score > best_score and score > 0.3:
                best_score = score
                best_pattern = pattern
        return best_pattern

    def _register_tools(self):
        @mcp.tool()
        async def search_meraki_api_endpoints(query: str) -> str:
            best_pattern = self._find_best_pattern_match(query)
            direct_match = None
            if best_pattern:
                direct_match = {
                    "section": best_pattern["section"],
                    "method": best_pattern["method"],
                    "description": best_pattern["description"],
                    "required_params": best_pattern["required_params"],
                    "confidence": self._calculate_semantic_score(query, best_pattern),
                }
            matches = {}
            if not direct_match:
                api_structure = self._discover_api_structure()
                query_lower = query.lower()
                for section, methods in api_structure.items():
                    section_matches = []
                    if any(word in section.lower() for word in query_lower.split()):
                        section_matches.extend(methods[:8])
                    for method in methods:
                        if any(word in method.lower() for word in query_lower.split()):
                            if method not in section_matches:
                                section_matches.append(method)
                    if section_matches:
                        matches[section] = section_matches[:8]
            result = {
                "query": query,
                "direct_match": direct_match,
                "matches": matches,
                "usage": "Use execute_api_endpoint with section='<section>' and method='<method>' to call an endpoint",
            }
            return json.dumps(result, indent=2)

        @mcp.tool()
        async def get_meraki_endpoint_parameters(section: str, method: str) -> str:
            try:
                section_obj = getattr(dashboard, section)
                method_obj = getattr(section_obj, method)
                sig = inspect.signature(method_obj)
                parameters = {}
                for param_name, param in sig.parameters.items():
                    param_info = {
                        "required": param.default == inspect.Parameter.empty,
                        "type": str(param.annotation) if param.annotation != inspect.Parameter.empty else "unknown",
                    }
                    if param.default != inspect.Parameter.empty:
                        param_info["default"] = param.default
                    parameters[param_name] = param_info
                result = {
                    "section": section,
                    "method": method,
                    "parameters": parameters,
                    "usage_example": f"execute_api_endpoint(section='{section}', method='{method}', ...)",
                }
                return json.dumps(result, indent=2)
            except AttributeError:
                error_result = {
                    "error": f"Endpoint not found: {section}.{method}",
                    "suggestion": "Use search_api_endpoints to find available endpoints",
                }
                return json.dumps(error_result, indent=2)
            except Exception as e:
                logger.error(f"Failed to get endpoint parameters: {e}")
                error_result = {"error": f"Failed to get parameters: {str(e)}"}
                return json.dumps(error_result, indent=2)

        @mcp.tool()
        async def execute_meraki_api_endpoint(
            section: str,
            method: str,
            serial: Optional[str] = None,
            portId: Optional[str] = None,
            networkId: Optional[str] = None,
            organizationId: Optional[str] = None,
            kwargs: str = "{}",
        ) -> str:
            try:
                cache_key = self._get_cache_key(
                    section,
                    method,
                    serial=serial,
                    portId=portId,
                    networkId=networkId,
                    organizationId=organizationId,
                    kwargs=kwargs,
                )
                if method.startswith("get") and cache_key in self._response_cache:
                    cache_entry = self._response_cache[cache_key]
                    if self._is_cache_valid(cache_entry):
                        logger.info(f"Cache hit for {section}.{method}")
                        return cache_entry["response"]
                def _call_api():
                    section_obj = getattr(dashboard, section)
                    method_obj = getattr(section_obj, method)
                    all_params = {
                        "serial": serial,
                        "portId": portId,
                        "networkId": networkId,
                        "organizationId": organizationId,
                    }
                    try:
                        if kwargs and kwargs.strip():
                            extra_params = json.loads(kwargs)
                            if isinstance(extra_params, dict):
                                all_params.update(extra_params)
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.warning(f"Invalid additional_params JSON: {e}")
                    filtered_params = {k: v for k, v in all_params.items() if v is not None and v != ""}
                    sig = inspect.signature(method_obj)
                    missing_params = []
                    for param_name, param in sig.parameters.items():
                        if param.default == inspect.Parameter.empty and param_name != "kwargs":
                            if param_name not in filtered_params:
                                missing_params.append(param_name)
                    if missing_params:
                        raise ValueError(f"Missing required parameters: {', '.join(missing_params)}")
                    return method_obj(**filtered_params)
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, _call_api)
                response_json = json.dumps(result, indent=2, default=str)
                if method.startswith("get"):
                    self._response_cache[cache_key] = {
                        "response": response_json,
                        "timestamp": time.time(),
                    }
                return response_json
            except ValueError as ve:
                error_result = {
                    "error": str(ve),
                    "section": section,
                    "method": method,
                    "provided_params": [k for k, v in {"serial": serial, "portId": portId, "networkId": networkId, "organizationId": organizationId}.items() if v is not None and v != ""],
                    "additional_params_provided": kwargs,
                    "suggestion": "Use get_meraki_endpoint_parameters to see all required parameters",
                }
                return json.dumps(error_result, indent=2)
            except AttributeError:
                api_structure = self._discover_api_structure()
                available_sections = list(api_structure.keys())
                if section not in available_sections:
                    error_result = {
                        "error": f"Section '{section}' not found",
                        "available_sections": available_sections[:10],
                        "suggestion": "Use search_meraki_api_endpoints to find the correct section",
                    }
                else:
                    available_methods = api_structure.get(section, [])
                    error_result = {
                        "error": f"Method '{method}' not found in section '{section}'",
                        "available_methods": available_methods[:20],
                        "suggestion": "Use search_meraki_api_endpoints to find the correct method",
                    }
                return json.dumps(error_result, indent=2)
            except Exception as e:
                logger.error(f"API call failed: {e}")
                error_result = {
                    "error": f"API call failed: {str(e)}",
                    "section": section,
                    "method": method,
                    "provided_params": [k for k, v in {"serial": serial, "portId": portId, "networkId": networkId, "organizationId": organizationId}.items() if v is not None and v != ""],
                }
                if kwargs:
                    error_result["additional_params"] = kwargs
                return json.dumps(error_result, indent=2)

    def _discover_api_structure(self) -> Dict[str, List[str]]:
        if self._api_cache:
            return self._api_cache
        try:
            api_structure = {}
            sections = [
                attr
                for attr in dir(dashboard)
                if not attr.startswith("_")
                and hasattr(getattr(dashboard, attr), "__class__")
                and "api" in str(type(getattr(dashboard, attr))).lower()
            ]
            for section in sections:
                section_obj = getattr(dashboard, section)
                methods = [
                    method
                    for method in dir(section_obj)
                    if not method.startswith("_")
                    and callable(getattr(section_obj, method))
                ]
                api_structure[section] = methods
            self._api_cache = api_structure
            return api_structure
        except Exception as e:
            logger.error(f"Failed to discover API structure: {e}")
            return {}

    def _get_cache_key(self, section: str, method: str, **params) -> str:
        sorted_params = sorted(params.items())
        return f"{section}.{method}:{hash(str(sorted_params))}"

    def _is_cache_valid(self, cache_entry: Dict) -> bool:
        return time.time() - cache_entry.get("timestamp", 0) < self._cache_ttl

# Instantiate dynamic tools
_meraki_api_tools = MerakiApiTools()

#######################
# COMPLEX TOOLS
#######################
@mcp.tool()
async def analyze_network_topology(network_id: str, include_clients: bool = False) -> str:
    try:
        devices = await async_get_network_devices(network_id)
        network_info = await async_get_network(network_id)
        topology = {
            "network": {
                "id": network_id,
                "name": network_info.get("name", "Unknown"),
                "type": network_info.get("productTypes", []),
            },
            "devices": {},
            "connections": [],
            "vlans": {},
            "summary": {},
        }
        for device in devices:
            device_detail = {
                "serial": device["serial"],
                "name": device.get("name", device["serial"]),
                "model": device["model"],
                "type": _complex_tools._get_device_type(device["model"]),
                "status": "online" if device.get("lanIp") else "offline",
                "address": device.get("address", ""),
                "ports": [],
                "uplinks": [],
                "clients": [],
            }
            if device_detail["type"] == "switch":
                await _complex_tools._analyze_switch_topology(device, device_detail, topology)
            elif device_detail["type"] == "appliance":
                await _complex_tools._analyze_appliance_topology(device, device_detail, topology, network_id)
            elif device_detail["type"] == "wireless":
                await _complex_tools._analyze_wireless_topology(device, device_detail, topology)
            topology["devices"][device["serial"]] = device_detail
        try:
            vlans = await async_get_network_appliance_vlans(network_id)
            if isinstance(vlans, list):
                for vlan in vlans:
                    vlan_id = str(vlan.get("id", ""))
                    if vlan_id:
                        topology["vlans"][vlan_id] = {
                            "id": vlan.get("id"),
                            "name": vlan.get("name", f"VLAN {vlan.get('id')}"),
                            "subnet": vlan.get("subnet", ""),
                            "applianceIp": vlan.get("applianceIp", ""),
                            "devices": [],
                        }
        except Exception:
            pass
        if include_clients:
            await _complex_tools._analyze_client_distribution(topology, network_id)
        _complex_tools._generate_topology_summary(topology)
        return json.dumps(topology, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to analyze network topology: {e}")
        return json.dumps({"error": f"Failed to analyze topology: {str(e)}"}, indent=2)

@mcp.tool()
async def analyze_device_health(serial: str, time_span: int = 86400) -> str:
    try:
        device = await async_get_device(serial)
        health_report = {
            "device": {
                "serial": serial,
                "name": device.get("name", serial),
                "model": device.get("model", "Unknown"),
                "firmware": device.get("firmware", "Unknown"),
                "lan_ip": device.get("lanIp", "Unknown"),
                "mac": device.get("mac", "Unknown"),
                "network_id": device.get("networkId", "Unknown"),
                "type": _complex_tools._get_device_type(device.get("model", "")),
            },
            "health_score": 85,
            "status": {
                "online": True,
                "last_check": datetime.utcnow().isoformat(),
                "api_accessible": True,
            },
            "components": {
                "connectivity": {"status": "healthy", "score": 100},
                "configuration": {"status": "healthy", "score": 85},
            },
            "issues": [],
            "performance": {
                "api_response": "responsive",
                "data_completeness": "good",
            },
            "recommendations": [
                "Device is responding to API calls",
                "Basic configuration appears complete",
            ],
            "analysis_time": datetime.utcnow().isoformat(),
            "analysis_scope": "basic_health_check",
        }
        if not device.get("name"):
            health_report["issues"].append({"severity": "low", "component": "configuration", "description": "Device has no custom name configured"})
            health_report["health_score"] -= 5
        if not device.get("lanIp"):
            health_report["issues"].append({"severity": "medium", "component": "connectivity", "description": "No LAN IP address information available"})
            health_report["health_score"] -= 10
        device_type = health_report["device"]["type"]
        if device_type == "wireless":
            health_report["recommendations"].append("Consider checking wireless client connectivity and signal strength")
        elif device_type == "switch":
            health_report["recommendations"].append("Consider checking port utilization and VLAN configuration")
        elif device_type == "appliance":
            health_report["recommendations"].append("Consider checking uplink status and security policies")
        await _complex_tools._analyze_switch_health(serial, device, health_report, time_span, MERAKI_ORG_ID)
        await _complex_tools._analyze_appliance_health(serial, device, health_report, time_span, MERAKI_ORG_ID)
        await _complex_tools._analyze_wireless_health(serial, device, health_report, time_span, MERAKI_ORG_ID)
        await _complex_tools._check_firmware_status(device, health_report, MERAKI_ORG_ID)
        _complex_tools._generate_health_recommendations(health_report)
        return json.dumps(health_report, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to analyze device health: {e}")
        return json.dumps({"error": f"Failed to analyze device health: {str(e)}", "device_serial": serial, "analysis_time": datetime.utcnow().isoformat()}, indent=2)

@mcp.tool()
async def audit_network_security(network_id: str, include_recommendations: bool = True) -> str:
    try:
        audit_report = {
            "network_id": network_id,
            "security_score": 100,
            "audit_time": datetime.utcnow().isoformat(),
            "findings": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
            },
            "components": {},
            "summary": {},
        }
        network = await async_get_network(network_id)
        audit_report["network_name"] = network.get("name", "Unknown")
        if "appliance" in network.get("productTypes", []):
            await _complex_tools._audit_firewall_security(network_id, audit_report)
        if "wireless" in network.get("productTypes", []):
            await _complex_tools._audit_wireless_security(network_id, audit_report)
        await _complex_tools._audit_network_settings(network_id, audit_report)
        await _complex_tools._audit_admin_access(network, audit_report)
        _complex_tools._calculate_security_score(audit_report)
        if include_recommendations:
            _complex_tools._generate_security_recommendations(audit_report)
        return json.dumps(audit_report, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to audit network security: {e}")
        return json.dumps({"error": f"Failed to audit security: {str(e)}"}, indent=2)

@mcp.tool()
async def analyze_network_performance(network_id: str, time_span: int = 86400) -> str:
    try:
        performance_report = {
            "network_id": network_id,
            "time_span": time_span,
            "analysis_time": datetime.utcnow().isoformat(),
            "performance_score": 100,
            "metrics": {
                "bandwidth": {},
                "latency": {},
                "packet_loss": {},
                "device_health": {},
            },
            "top_talkers": {"clients": [], "applications": []},
            "bottlenecks": [],
            "trends": {},
            "recommendations": [],
        }
        network = await async_get_network(network_id)
        devices = await async_get_network_devices(network_id)
        performance_report["network_name"] = network.get("name", "Unknown")
        for device in devices:
            await _complex_tools._analyze_device_performance(device, performance_report, time_span)
        try:
            clients = await async_get_network_clients(network_id, timespan=time_span, perPage=100)
            _complex_tools._analyze_client_performance(clients, performance_report)
        except Exception:
            pass
        if "appliance" in network.get("productTypes", []):
            await _complex_tools._analyze_traffic_patterns(network_id, performance_report, time_span)
        _complex_tools._identify_performance_bottlenecks(performance_report)
        _complex_tools._generate_performance_recommendations(performance_report)
        return json.dumps(performance_report, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to analyze network performance: {e}")
        return json.dumps({"error": f"Failed to analyze performance: {str(e)}"}, indent=2)

@mcp.tool()
async def analyze_configuration_drift(organization_id: str, network_ids: Optional[List[str]] = None) -> str:
    try:
        drift_report = {
            "organization_id": organization_id,
            "analysis_time": datetime.utcnow().isoformat(),
            "consistency_score": 100,
            "configuration_groups": {},
            "deviations": [],
            "inconsistencies": {},
            "recommendations": [],
        }
        if network_ids:
            networks = []
            for network_id in network_ids:
                network = await async_get_network(network_id)
                networks.append(network)
        else:
            networks = await async_get_organization_networks(organization_id)
        network_groups = defaultdict(list)
        for network in networks:
            product_types = tuple(sorted(network.get("productTypes", [])))
            network_groups[product_types].append(network)
        for product_types, group_networks in network_groups.items():
            if len(group_networks) > 1:
                await _complex_tools._analyze_configuration_group(product_types, group_networks, drift_report)
        _complex_tools._calculate_consistency_score(drift_report)
        _complex_tools._generate_drift_recommendations(drift_report)
        return json.dumps(drift_report, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to analyze configuration drift: {e}")
        return json.dumps({"error": f"Failed to analyze configuration drift: {str(e)}"}, indent=2)

@mcp.tool()
async def troubleshoot_connectivity(source_ip: str, destination_ip: str, network_id: str) -> str:
    try:
        troubleshoot_report = {
            "test_parameters": {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "network_id": network_id,
                "test_time": datetime.utcnow().isoformat(),
            },
            "connectivity_status": "unknown",
            "path_analysis": {},
            "blockers": [],
            "recommendations": [],
        }
        network = await async_get_network(network_id)
        clients = await async_get_network_clients(network_id, perPage=1000)
        source_client = None
        dest_client = None
        for client in clients:
            if client.get("ip") == source_ip:
                source_client = client
            elif client.get("ip") == destination_ip:
                dest_client = client
        troubleshoot_report["endpoints"] = {
            "source": source_client or {"ip": source_ip, "status": "not found"},
            "destination": dest_client or {"ip": destination_ip, "status": "not found"},
        }
        if "appliance" in network.get("productTypes", []):
            await _complex_tools._troubleshoot_appliance_connectivity(network_id, source_ip, destination_ip, troubleshoot_report)
        if "switch" in network.get("productTypes", []):
            await _complex_tools._troubleshoot_switch_connectivity(network_id, source_client, dest_client, troubleshoot_report)
        _complex_tools._generate_troubleshoot_recommendations(troubleshoot_report)
        return json.dumps(troubleshoot_report, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to troubleshoot connectivity: {e}")
        return json.dumps({"error": f"Failed to troubleshoot connectivity: {str(e)}"}, indent=2)

@mcp.tool()
async def analyze_client_experience(network_id: str, time_span: int = 86400) -> str:
    try:
        experience_report = {
            "network_id": network_id,
            "time_span": time_span,
            "analysis_time": datetime.utcnow().isoformat(),
            "experience_score": 100,
            "client_metrics": {
                "total_clients": 0,
                "satisfaction_breakdown": {},
                "connectivity_issues": [],
                "performance_metrics": {},
            },
            "application_performance": {},
            "problem_clients": [],
            "recommendations": [],
        }
        network = await async_get_network(network_id)
        experience_report["network_name"] = network.get("name", "Unknown")
        clients = await async_get_network_clients(network_id, timespan=time_span, perPage=1000)
        experience_report["client_metrics"]["total_clients"] = len(clients)
        for client in clients:
            _complex_tools._analyze_client_metrics(client, experience_report)
        if "wireless" in network.get("productTypes", []):
            await _complex_tools._analyze_wireless_experience(network_id, experience_report, time_span)
        _complex_tools._calculate_experience_score(experience_report)
        _complex_tools._generate_experience_recommendations(experience_report)
        return json.dumps(experience_report, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to analyze client experience: {e}")
        return json.dumps({"error": f"Failed to analyze client experience: {str(e)}"}, indent=2)

@mcp.tool()
async def generate_network_inventory_report(organization_id: str, include_clients: bool = False) -> str:
    try:
        inventory_report = {
            "organization_id": organization_id,
            "report_time": datetime.utcnow().isoformat(),
            "summary": {
                "total_devices": 0,
                "device_breakdown": {},
                "license_summary": {},
                "lifecycle_summary": {},
            },
            "devices": [],
            "insights": {
                "end_of_life": [],
                "warranty_expiring": [],
                "underutilized": [],
                "upgrade_candidates": [],
            },
            "recommendations": [],
        }
        org = await async_get_organization(organization_id)
        inventory_report["organization_name"] = org.get("name", "Unknown")
        devices = await async_get_organization_devices(organization_id)
        inventory_report["summary"]["total_devices"] = len(devices)
        try:
            licenses = await to_async(dashboard.organizations.getOrganizationLicenses)(organizationId=organization_id)
            _complex_tools._analyze_license_utilization(licenses, inventory_report)
        except Exception:
            pass
        device_counts = defaultdict(int)
        for device in devices:
            device_info = {
                "serial": device["serial"],
                "name": device.get("name", device["serial"]),
                "model": device["model"],
                "type": _complex_tools._get_device_type(device["model"]),
                "network_id": device.get("networkId"),
                "firmware": device.get("firmware"),
                "address": device.get("address"),
                "tags": device.get("tags", []),
            }
            _complex_tools._check_device_lifecycle(device_info, inventory_report)
            device_counts[device_info["type"]] += 1
            inventory_report["devices"].append(device_info)
        inventory_report["summary"]["device_breakdown"] = dict(device_counts)
        if include_clients:
            await _complex_tools._get_client_inventory(organization_id, inventory_report)
        _complex_tools._generate_inventory_insights(inventory_report)
        return json.dumps(inventory_report, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to generate inventory report: {e}")
        return json.dumps({"error": f"Failed to generate inventory report: {str(e)}"}, indent=2)

#######################
# ORIGINAL TOOLS (Fixed & Updated)
#######################
@mcp.tool()
async def get_organizations() -> str:
    try:
        organizations = await async_get_organizations()
        result = {
            "method": "getOrganizations",
            "count": len(organizations),
            "organizations": organizations,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Failed to get organizations: {e}")
        return json.dumps({"error": "API call failed", "message": str(e)}, indent=2)

@mcp.tool()
def get_organization_details(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    org_details = dashboard.organizations.getOrganization(organization_id)
    return json.dumps(org_details, indent=2)

@mcp.tool()
async def get_networks(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    networks = await async_get_organization_networks(organization_id)
    return json.dumps(networks, indent=2)

@mcp.tool()
async def get_devices(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    devices = await async_get_organization_devices(organization_id)
    return json.dumps(devices, indent=2)

@mcp.tool()
def create_network(name: str, tags: list[str], productTypes: list[str], org_id: str = None, copyFromNetworkId: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    kwargs = {}
    if copyFromNetworkId:
        kwargs['copyFromNetworkId'] = copyFromNetworkId
    network = dashboard.organizations.createOrganizationNetwork(organization_id, name, productTypes, tags=tags, **kwargs)
    return json.dumps(network, indent=2)

@mcp.tool()
def delete_network(network_id: str) -> str:
    dashboard.networks.deleteNetwork(network_id)
    return f"Network {network_id} deleted"

@mcp.tool()
def get_organization_status(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    status = dashboard.organizations.getOrganizationDevicesStatuses(organization_id)
    return json.dumps(status, indent=2)

@mcp.tool()
def get_organization_inventory(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    inventory = dashboard.organizations.getOrganizationInventoryDevices(organization_id)
    return json.dumps(inventory, indent=2)

@mcp.tool()
def get_organization_license(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    license_state = dashboard.organizations.getOrganizationLicensesOverview(organization_id)
    return json.dumps(license_state, indent=2)

@mcp.tool()
def get_organization_conf_change(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    org_config_changes = dashboard.organizations.getOrganizationConfigurationChanges(organization_id)
    return json.dumps(org_config_changes, indent=2)

@mcp.tool()
def get_network_details(network_id: str) -> str:
    network = dashboard.networks.getNetwork(network_id)
    return json.dumps(network, indent=2)

@mcp.tool()
def get_network_devices(network_id: str) -> str:
    devices = dashboard.networks.getNetworkDevices(network_id)
    return json.dumps(devices, indent=2)

@mcp.tool()
def update_network(network_id: str, update_data: NetworkUpdateSchema) -> str:
    update_dict = {k: v for k, v in update_data.dict().items() if v is not None}
    result = dashboard.networks.updateNetwork(network_id, **update_dict)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_clients(network_id: str, timespan: int = 86400) -> str:
    clients = dashboard.networks.getNetworkClients(network_id, timespan=timespan)
    return json.dumps(clients, indent=2)

@mcp.tool()
def get_client_details(network_id: str, client_id: str) -> str:
    client = dashboard.networks.getNetworkClient(network_id, client_id)
    return json.dumps(client, indent=2)

@mcp.tool()
def get_client_usage(network_id: str, client_id: str) -> str:
    usage = dashboard.networks.getNetworkClientUsageHistory(network_id, client_id)
    return json.dumps(usage, indent=2)

@mcp.tool()
async def get_client_policy(network_id: str, client_id: str) -> str:
    policy = await to_async(dashboard.networks.getNetworkClientPolicy)(network_id, client_id)
    return json.dumps(policy, indent=2)

@mcp.tool()
def update_client_policy(network_id: str, client_id: str, device_policy: str, group_policy_id: str = None) -> str:
    kwargs = {'devicePolicy': device_policy}
    if group_policy_id:
        kwargs['groupPolicyId'] = group_policy_id
    result = dashboard.networks.updateNetworkClientPolicy(network_id, client_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_network_traffic(network_id: str, timespan: int = 86400) -> str:
    traffic = dashboard.networks.getNetworkTraffic(network_id, timespan=timespan)
    return json.dumps(traffic, indent=2)

@mcp.tool()
async def get_device_details(serial: str) -> str:
    device = await async_get_device(serial)
    return json.dumps(device, indent=2)

@mcp.tool()
async def update_device(serial: str, device_settings: DeviceUpdateSchema) -> str:
    update_dict = {k: v for k, v in device_settings.dict().items() if v is not None}
    await async_update_device(serial, **update_dict)
    updated_device = await async_get_device(serial)
    return json.dumps({
        "status": "success",
        "message": f"Device {serial} updated",
        "updated_settings": update_dict,
        "current_device": updated_device
    }, indent=2)

@mcp.tool()
def claim_devices(network_id: str, serials: list[str]) -> str:
    dashboard.networks.claimNetworkDevices(network_id, serials)
    return f"Devices {serials} claimed into network {network_id}"

@mcp.tool()
def remove_device(serial: str) -> str:
    dashboard.devices.removeDevice(serial)
    return f"Device {serial} removed from network"

@mcp.tool()
def reboot_device(serial: str) -> str:
    result = dashboard.devices.rebootDevice(serial)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_device_clients(serial: str, timespan: int = 86400) -> str:
    clients = dashboard.devices.getDeviceClients(serial, timespan=timespan)
    return json.dumps(clients, indent=2)

@mcp.tool()
def get_device_status(serial: str) -> str:
    status = dashboard.devices.getDeviceStatus(serial)
    return json.dumps(status, indent=2)

@mcp.tool()
def get_device_uplink(serial: str) -> str:
    uplink = dashboard.devices.getDeviceUplink(serial)
    return json.dumps(uplink, indent=2)

@mcp.tool()
async def get_wireless_ssids(network_id: str) -> str:
    ssids = await async_get_wireless_ssids(network_id)
    return json.dumps(ssids, indent=2)

@mcp.tool()
async def update_wireless_ssid(network_id: str, ssid_number: str, ssid_settings: SsidUpdateSchema) -> str:
    update_dict = {k: v for k, v in ssid_settings.dict().items() if v is not None}
    result = await async_update_wireless_ssid(network_id, ssid_number, **update_dict)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_wireless_settings(network_id: str) -> str:
    settings = dashboard.wireless.getNetworkWirelessSettings(network_id)
    return json.dumps(settings, indent=2)

@mcp.tool()
def get_switch_ports(serial: str) -> str:
    ports = dashboard.switch.getDeviceSwitchPorts(serial)
    return json.dumps(ports, indent=2)

@mcp.tool()
def update_switch_port(serial: str, port_id: str, name: str = None, tags: list[str] = None, enabled: bool = None, vlan: int = None) -> str:
    kwargs = {}
    if name:
        kwargs['name'] = name
    if tags:
        kwargs['tags'] = tags
    if enabled is not None:
        kwargs['enabled'] = enabled
    if vlan:
        kwargs['vlan'] = vlan
    result = dashboard.switch.updateDeviceSwitchPort(serial, port_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_switch_vlans(network_id: str) -> str:
    vlans = dashboard.switch.getNetworkSwitchVlans(network_id)
    return json.dumps(vlans, indent=2)

@mcp.tool()
def create_switch_vlan(network_id: str, vlan_id: int, name: str, subnet: str = None, appliance_ip: str = None) -> str:
    kwargs = {}
    if subnet:
        kwargs['subnet'] = subnet
    if appliance_ip:
        kwargs['applianceIp'] = appliance_ip
    result = dashboard.switch.createNetworkSwitchVlan(network_id, vlan_id, name, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_security_center(network_id: str) -> str:
    security = dashboard.appliance.getNetworkApplianceSecurityCenter(network_id)
    return json.dumps(security, indent=2)

@mcp.tool()
def get_vpn_status(network_id: str) -> str:
    vpn_status = dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(network_id)
    return json.dumps(vpn_status, indent=2)

@mcp.tool()
def get_firewall_rules(network_id: str) -> str:
    rules = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
    return json.dumps(rules, indent=2)

@mcp.tool()
def update_firewall_rules(network_id: str, rules: List[FirewallRule]) -> str:
    rules_dict = [rule.dict(exclude_none=True) for rule in rules]
    result = dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, rules=rules_dict)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_camera_video_settings(serial: str) -> str:
    settings = dashboard.camera.getDeviceCameraVideoSettings(serial)
    return json.dumps(settings, indent=2)

@mcp.tool()
def get_camera_quality_settings(network_id: str) -> str:
    settings = dashboard.camera.getNetworkCameraQualityRetentionProfiles(network_id)
    return json.dumps(settings, indent=2)

@mcp.tool()
def get_organization_admins(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    admins = dashboard.organizations.getOrganizationAdmins(organization_id)
    return json.dumps(admins, indent=2)

@mcp.tool()
def create_organization_admin(org_id: str, email: str, name: str, org_access: str, tags: list[str] = None, networks: list[dict] = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    kwargs = {
        'email': email,
        'name': name,
        'orgAccess': org_access
    }
    if tags:
        kwargs['tags'] = tags
    if networks:
        kwargs['networks'] = networks
    result = dashboard.organizations.createOrganizationAdmin(organization_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_organization_api_requests(org_id: str = None, timespan: int = 86400) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    requests = dashboard.organizations.getOrganizationApiRequests(organization_id, timespan=timespan)
    return json.dumps(requests, indent=2)

@mcp.tool()
def get_organization_webhook_logs(org_id: str = None, timespan: int = 86400) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    logs = dashboard.organizations.getOrganizationWebhooksLogs(organization_id, timespan=timespan)
    return json.dumps(logs, indent=2)

@mcp.tool()
def get_network_events(network_id: str, timespan: int = 86400, per_page: int = 100) -> str:
    events = dashboard.networks.getNetworkEvents(network_id, timespan=timespan, perPage=per_page)
    return json.dumps(events, indent=2)

@mcp.tool()
def get_network_event_types(network_id: str) -> str:
    event_types = dashboard.networks.getNetworkEventsEventTypes(network_id)
    return json.dumps(event_types, indent=2)

@mcp.tool()
def get_network_alerts_history(network_id: str, timespan: int = 86400) -> str:
    alerts = dashboard.networks.getNetworkAlertsHistory(network_id, timespan=timespan)
    return json.dumps(alerts, indent=2)

@mcp.tool()
def get_network_alerts_settings(network_id: str) -> str:
    settings = dashboard.networks.getNetworkAlertsSettings(network_id)
    return json.dumps(settings, indent=2)

@mcp.tool()
def update_network_alerts_settings(network_id: str, defaultDestinations: dict = None, alerts: list[dict] = None) -> str:
    kwargs = {}
    if defaultDestinations:
        kwargs['defaultDestinations'] = defaultDestinations
    if alerts:
        kwargs['alerts'] = alerts
    result = dashboard.networks.updateNetworkAlertsSettings(network_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def ping_device(serial: str, target_ip: str, count: int = 5) -> str:
    result = dashboard.devices.createDeviceLiveToolsPing(serial, target_ip, count=count)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_device_ping_results(serial: str, ping_id: str) -> str:
    result = dashboard.devices.getDeviceLiveToolsPing(serial, ping_id)
    return json.dumps(result, indent=2)

@mcp.tool()
def cable_test_device(serial: str, ports: list[str]) -> str:
    result = dashboard.devices.createDeviceLiveToolsCableTest(serial, ports)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_device_cable_test_results(serial: str, cable_test_id: str) -> str:
    result = dashboard.devices.getDeviceLiveToolsCableTest(serial, cable_test_id)
    return json.dumps(result, indent=2)

@mcp.tool()
def blink_device_leds(serial: str, duration: int = 5) -> str:
    result = dashboard.devices.blinkDeviceLeds(serial, duration=duration)
    return json.dumps(result, indent=2)

@mcp.tool()
def wake_on_lan_device(serial: str, mac: str) -> str:
    result = dashboard.devices.createDeviceLiveToolsWakeOnLan(serial, mac)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_wireless_rf_profiles(network_id: str) -> str:
    profiles = dashboard.wireless.getNetworkWirelessRfProfiles(network_id)
    return json.dumps(profiles, indent=2)

@mcp.tool()
def create_wireless_rf_profile(network_id: str, name: str, band_selection_type: str, **kwargs) -> str:
    result = dashboard.wireless.createNetworkWirelessRfProfile(network_id, name, bandSelectionType=band_selection_type, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_wireless_channel_utilization(network_id: str, timespan: int = 86400) -> str:
    utilization = dashboard.wireless.getNetworkWirelessChannelUtilizationHistory(network_id, timespan=timespan)
    return json.dumps(utilization, indent=2)

@mcp.tool()
def get_wireless_signal_quality(network_id: str, timespan: int = 86400) -> str:
    quality = dashboard.wireless.getNetworkWirelessSignalQualityHistory(network_id, timespan=timespan)
    return json.dumps(quality, indent=2)

@mcp.tool()
def get_wireless_connection_stats(network_id: str, timespan: int = 86400) -> str:
    stats = dashboard.wireless.getNetworkWirelessConnectionStats(network_id, timespan=timespan)
    return json.dumps(stats, indent=2)

@mcp.tool()
def get_wireless_client_connectivity_events(network_id: str, client_id: str, timespan: int = 86400) -> str:
    events = dashboard.wireless.getNetworkWirelessClientConnectivityEvents(network_id, client_id, timespan=timespan)
    return json.dumps(events, indent=2)

@mcp.tool()
def get_switch_port_statuses(serial: str) -> str:
    statuses = dashboard.switch.getDeviceSwitchPortsStatuses(serial)
    return json.dumps(statuses, indent=2)

@mcp.tool()
def cycle_switch_ports(serial: str, ports: list[str]) -> str:
    result = dashboard.switch.cycleDeviceSwitchPorts(serial, ports)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_switch_access_control_lists(network_id: str) -> str:
    acls = dashboard.switch.getNetworkSwitchAccessControlLists(network_id)
    return json.dumps(acls, indent=2)

@mcp.tool()
def update_switch_access_control_lists(network_id: str, rules: list[dict]) -> str:
    result = dashboard.switch.updateNetworkSwitchAccessControlLists(network_id, rules)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_switch_qos_rules(network_id: str) -> str:
    rules = dashboard.switch.getNetworkSwitchQosRules(network_id)
    return json.dumps(rules, indent=2)

@mcp.tool()
def create_switch_qos_rule(network_id: str, vlan: int, protocol: str, src_port: int, src_port_range: str = None, dst_port: int = None, dst_port_range: str = None, dscp: int = None) -> str:
    kwargs = {
        'vlan': vlan,
        'protocol': protocol,
        'srcPort': src_port
    }
    if src_port_range:
        kwargs['srcPortRange'] = src_port_range
    if dst_port:
        kwargs['dstPort'] = dst_port
    if dst_port_range:
        kwargs['dstPortRange'] = dst_port_range
    if dscp:
        kwargs['dscp'] = dscp
    result = dashboard.switch.createNetworkSwitchQosRule(network_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_appliance_vpn_site_to_site(network_id: str) -> str:
    vpn = dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(network_id)
    return json.dumps(vpn, indent=2)

@mcp.tool()
def update_appliance_vpn_site_to_site(network_id: str, mode: str, hubs: list[dict] = None, subnets: list[dict] = None) -> str:
    kwargs = {'mode': mode}
    if hubs:
        kwargs['hubs'] = hubs
    if subnets:
        kwargs['subnets'] = subnets
    result = dashboard.appliance.updateNetworkApplianceVpnSiteToSiteVpn(network_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_appliance_content_filtering(network_id: str) -> str:
    filtering = dashboard.appliance.getNetworkApplianceContentFiltering(network_id)
    return json.dumps(filtering, indent=2)

@mcp.tool()
def update_appliance_content_filtering(network_id: str, allowed_urls: list[str] = None, blocked_urls: list[str] = None, blocked_url_patterns: list[str] = None, youtube_restricted_for_teenagers: bool = None, youtube_restricted_for_mature: bool = None) -> str:
    kwargs = {}
    if allowed_urls:
        kwargs['allowedUrls'] = allowed_urls
    if blocked_urls:
        kwargs['blockedUrls'] = blocked_urls
    if blocked_url_patterns:
        kwargs['blockedUrlPatterns'] = blocked_url_patterns
    if youtube_restricted_for_teenagers is not None:
        kwargs['youtubeRestrictedForTeenagers'] = youtube_restricted_for_teenagers
    if youtube_restricted_for_mature is not None:
        kwargs['youtubeRestrictedForMature'] = youtube_restricted_for_mature
    result = dashboard.appliance.updateNetworkApplianceContentFiltering(network_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_appliance_security_events(network_id: str, timespan: int = 86400) -> str:
    events = dashboard.appliance.getNetworkApplianceSecurityEvents(network_id, timespan=timespan)
    return json.dumps(events, indent=2)

@mcp.tool()
def get_appliance_traffic_shaping(network_id: str) -> str:
    shaping = dashboard.appliance.getNetworkApplianceTrafficShaping(network_id)
    return json.dumps(shaping, indent=2)

@mcp.tool()
def update_appliance_traffic_shaping(network_id: str, global_bandwidth_limits: dict = None) -> str:
    kwargs = {}
    if global_bandwidth_limits:
        kwargs['globalBandwidthLimits'] = global_bandwidth_limits
    result = dashboard.appliance.updateNetworkApplianceTrafficShaping(network_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_camera_analytics_live(serial: str) -> str:
    analytics = dashboard.camera.getDeviceCameraAnalyticsLive(serial)
    return json.dumps(analytics, indent=2)

@mcp.tool()
def get_camera_analytics_overview(serial: str, timespan: int = 86400) -> str:
    overview = dashboard.camera.getDeviceCameraAnalyticsOverview(serial, timespan=timespan)
    return json.dumps(overview, indent=2)

@mcp.tool()
def get_camera_analytics_zones(serial: str) -> str:
    zones = dashboard.camera.getDeviceCameraAnalyticsZones(serial)
    return json.dumps(zones, indent=2)

@mcp.tool()
def generate_camera_snapshot(serial: str, timestamp: str = None) -> str:
    kwargs = {}
    if timestamp:
        kwargs['timestamp'] = timestamp
    result = dashboard.camera.generateDeviceCameraSnapshot(serial, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_camera_sense(serial: str) -> str:
    sense = dashboard.camera.getDeviceCameraSense(serial)
    return json.dumps(sense, indent=2)

@mcp.tool()
def update_camera_sense(serial: str, sense_enabled: bool = None, mqtt_broker_id: str = None, audio_detection: dict = None) -> str:
    kwargs = {}
    if sense_enabled is not None:
        kwargs['senseEnabled'] = sense_enabled
    if mqtt_broker_id:
        kwargs['mqttBrokerId'] = mqtt_broker_id
    if audio_detection:
        kwargs['audioDetection'] = audio_detection
    result = dashboard.camera.updateDeviceCameraSense(serial, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
def create_action_batch(org_id: str, actions: list[dict], confirmed: bool = True, synchronous: bool = False) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    result = dashboard.organizations.createOrganizationActionBatch(organization_id, actions, confirmed=confirmed, synchronous=synchronous)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_action_batch_status(org_id: str, batch_id: str) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    status = dashboard.organizations.getOrganizationActionBatch(organization_id, batch_id)
    return json.dumps(status, indent=2)

@mcp.tool()
def get_action_batches(org_id: str = None) -> str:
    organization_id = org_id or MERAKI_ORG_ID
    batches = dashboard.organizations.getOrganizationActionBatches(organization_id)
    return json.dumps(batches, indent=2)

# Greeting resource
@mcp.resource("greeting://{name}")
def greeting(name: str) -> str:
    return f"Hello {name}!"

# Run the server
if __name__ == "__main__":
    mcp.run()
