import os
import json
import meraki
import asyncio
import functools
from typing import Dict, List, Optional, Any, TypedDict, Union, Callable
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
from meraki.exceptions import APIError

# Load environment variables from .env file
load_dotenv()

# Create an MCP server
mcp = FastMCP("Meraki Magic MCP")

# Configuration
MERAKI_API_KEY = os.getenv("MERAKI_API_KEY")
MERAKI_ORG_ID = os.getenv("MERAKI_ORG_ID")

# Initialize Meraki API client using Meraki SDK
dashboard = meraki.DashboardAPI(api_key=MERAKI_API_KEY, suppress_logging=True)

###################
# ASYNC UTILITIES
###################

def to_async(func: Callable) -> Callable:
    """
    Convert a synchronous function to an asynchronous function

    Args:
        func: The synchronous function to convert

    Returns:
        An asynchronous version of the function
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: func(*args, **kwargs)
        )
    return wrapper

# Create async versions of commonly used Meraki API methods
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
async_create_network = to_async(dashboard.organizations.createOrganizationNetwork)
async_delete_network = to_async(dashboard.networks.deleteNetwork)
async_get_organization_inventory = to_async(dashboard.organizations.getOrganizationInventoryDevices)
async_get_organization_license = to_async(dashboard.organizations.getOrganizationLicensesOverview)
async_get_organization_conf_changes = to_async(dashboard.organizations.getOrganizationConfigurationChanges)
async_get_network_events = to_async(dashboard.networks.getNetworkEvents)
async_get_network_event_types = to_async(dashboard.networks.getNetworkEventsEventTypes)
async_get_network_alerts_history = to_async(dashboard.networks.getNetworkAlertsHistory)
async_get_network_alerts_settings = to_async(dashboard.networks.getNetworkAlertsSettings)
async_update_network_alerts_settings = to_async(dashboard.networks.updateNetworkAlertsSettings)
async_ping_device = to_async(dashboard.devices.createDeviceLiveToolsPing)
async_get_device_ping_results = to_async(dashboard.devices.getDeviceLiveToolsPing)
async_cable_test_device = to_async(dashboard.devices.createDeviceLiveToolsCableTest)
async_get_device_cable_test_results = to_async(dashboard.devices.getDeviceLiveToolsCableTest)
async_blink_device_leds = to_async(dashboard.devices.blinkDeviceLeds)
async_wake_on_lan_device = to_async(dashboard.devices.createDeviceLiveToolsWakeOnLan)
async_get_wireless_rf_profiles = to_async(dashboard.wireless.getNetworkWirelessRfProfiles)
async_create_wireless_rf_profile = to_async(dashboard.wireless.createNetworkWirelessRfProfile)
async_get_wireless_channel_utilization = to_async(dashboard.wireless.getNetworkWirelessChannelUtilizationHistory)
async_get_wireless_signal_quality = to_async(dashboard.wireless.getNetworkWirelessSignalQualityHistory)
async_get_wireless_connection_stats = to_async(dashboard.wireless.getNetworkWirelessConnectionStats)
async_get_wireless_client_connectivity_events = to_async(dashboard.wireless.getNetworkWirelessClientConnectivityEvents)
async_get_switch_port_statuses = to_async(dashboard.switch.getDeviceSwitchPortsStatuses)
async_cycle_switch_ports = to_async(dashboard.switch.cycleDeviceSwitchPorts)
async_get_switch_access_control_lists = to_async(dashboard.switch.getNetworkSwitchAccessControlLists)
async_update_switch_access_control_lists = to_async(dashboard.switch.updateNetworkSwitchAccessControlLists)
async_get_switch_qos_rules = to_async(dashboard.switch.getNetworkSwitchAccessControlLists)
async_create_switch_qos_rule = to_async(dashboard.switch.createNetworkSwitchQosRule)
async_get_appliance_vpn_site_to_site = to_async(dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn)
async_update_appliance_vpn_site_to_site = to_async(dashboard.appliance.updateNetworkApplianceVpnSiteToSiteVpn)
async_get_appliance_content_filtering = to_async(dashboard.appliance.getNetworkApplianceContentFiltering)
async_update_appliance_content_filtering = to_async(dashboard.appliance.updateNetworkApplianceContentFiltering)
async_get_appliance_security_events = to_async(dashboard.appliance.getNetworkApplianceSecurityEvents)
async_get_appliance_traffic_shaping = to_async(dashboard.appliance.getNetworkApplianceTrafficShaping)
async_update_appliance_traffic_shaping = to_async(dashboard.appliance.updateNetworkApplianceTrafficShaping)
async_get_camera_analytics_live = to_async(dashboard.camera.getDeviceCameraAnalyticsLive)
async_get_camera_analytics_overview = to_async(dashboard.camera.getDeviceCameraAnalyticsOverview)
async_get_camera_analytics_zones = to_async(dashboard.camera.getDeviceCameraAnalyticsZones)
async_generate_camera_snapshot = to_async(dashboard.camera.generateDeviceCameraSnapshot)
async_get_camera_sense = to_async(dashboard.camera.getDeviceCameraSense)
async_update_camera_sense = to_async(dashboard.camera.updateDeviceCameraSense)
async_create_action_batch = to_async(dashboard.organizations.createOrganizationActionBatch)
async_get_action_batch_status = to_async(dashboard.organizations.getOrganizationActionBatch)
async_get_action_batches = to_async(dashboard.organizations.getOrganizationActionBatches)

# New async wrappers based on spec
async_get_administered_identities_me = to_async(dashboard.administered.getAdministeredIdentitiesMe)
async_get_administered_identities_me_api_keys = to_async(dashboard.administered.getAdministeredIdentitiesMeApiKeys)
async_generate_administered_identities_me_api_keys = to_async(dashboard.administered.generateAdministeredIdentitiesMeApiKeys)
async_revoke_administered_identities_me_api_keys = to_async(dashboard.administered.revokeAdministeredIdentitiesMeApiKeys)

###################
# SCHEMA DEFINITIONS
###################

# Wireless SSID Schema
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

# Firewall Rule Schema
class FirewallRule(BaseModel):
    comment: str = Field(..., description="Description of the firewall rule")
    policy: str = Field(..., description="'allow' or 'deny'")
    protocol: str = Field(..., description="The protocol (e.g., 'tcp', 'udp', 'any')")
    srcPort: Optional[str] = Field("Any", description="Source port (e.g., '80', '443-8080', 'Any')")
    srcCidr: str = Field("Any", description="Source CIDR (e.g., '192.168.1.0/24', 'Any')")
    destPort: Optional[str] = Field("Any", description="Destination port (e.g., '80', '443-8080', 'Any')")
    destCidr: str = Field("Any", description="Destination CIDR (e.g., '192.168.1.0/24', 'Any')")
    syslogEnabled: Optional[bool] = Field(False, description="Whether syslog is enabled for this rule")

# Device Update Schema
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

# Network Update Schema
class NetworkUpdateSchema(BaseModel):
    name: Optional[str] = Field(None, description="The name of the network")
    timeZone: Optional[str] = Field(None, description="The timezone of the network")
    tags: Optional[List[str]] = Field(None, description="List of tags for the network")
    enrollmentString: Optional[str] = Field(None, description="Enrollment string for the network")
    notes: Optional[str] = Field(None, description="Notes for the network")

# Admin Creation Schema
class AdminCreationSchema(BaseModel):
    email: str = Field(..., description="Email address of the admin")
    name: str = Field(..., description="Name of the admin")
    orgAccess: str = Field(..., description="Access level for the organization")
    tags: Optional[List[str]] = Field(None, description="List of tags for the admin")
    networks: Optional[List[dict]] = Field(None, description="Network access for the admin")

# Action Batch Schema
class ActionBatchSchema(BaseModel):
    actions: List[dict] = Field(..., description="List of actions to perform")
    confirmed: bool = Field(True, description="Whether the batch is confirmed")
    synchronous: bool = Field(False, description="Whether the batch is synchronous")

# VPN Configuration Schema
class VpnSiteToSiteSchema(BaseModel):
    mode: str = Field(..., description="VPN mode (none, full, or hub-and-spoke)")
    hubs: Optional[List[dict]] = Field(None, description="List of hub configurations")
    subnets: Optional[List[dict]] = Field(None, description="List of subnet configurations")

# Content Filtering Schema
class ContentFilteringSchema(BaseModel):
    allowedUrls: Optional[List[str]] = Field(None, description="List of allowed URLs")
    blockedUrls: Optional[List[str]] = Field(None, description="List of blocked URLs")
    blockedUrlPatterns: Optional[List[str]] = Field(None, description="List of blocked URL patterns")
    youtubeRestrictedForTeenagers: Optional[bool] = Field(None, description="Restrict YouTube for teenagers")
    youtubeRestrictedForMature: Optional[bool] = Field(None, description="Restrict YouTube for mature content")

# Traffic Shaping Schema
class TrafficShapingSchema(BaseModel):
    globalBandwidthLimits: Optional[dict] = Field(None, description="Global bandwidth limits")
    rules: Optional[List[dict]] = Field(None, description="Traffic shaping rules")

# Camera Sense Schema
class CameraSenseSchema(BaseModel):
    senseEnabled: Optional[bool] = Field(None, description="Whether camera sense is enabled")
    mqttBrokerId: Optional[str] = Field(None, description="MQTT broker ID")
    audioDetection: Optional[dict] = Field(None, description="Audio detection settings")

# Switch QoS Rule Schema
class SwitchQosRuleSchema(BaseModel):
    vlan: int = Field(..., description="VLAN ID")
    protocol: str = Field(..., description="Protocol (tcp, udp, any)")
    srcPort: int = Field(..., description="Source port")
    srcPortRange: Optional[str] = Field(None, description="Source port range")
    dstPort: Optional[int] = Field(None, description="Destination port")
    dstPortRange: Optional[str] = Field(None, description="Destination port range")
    dscp: Optional[int] = Field(None, description="DSCP value")

# New Schemas from Spec

# Administered Identities Me Schema (for update if needed, but mostly get)
class AdministeredIdentitiesMeSchema(BaseModel):
    pass  # Mostly read-only, but can be used for extensions

# API Key Generation Schema
class ApiKeyGenerateSchema(BaseModel):
    pass  # No body needed

# API Key Revoke Schema
class ApiKeyRevokeSchema(BaseModel):
    suffix: str = Field(..., description="Last 4 characters of the API key")

# Subscription Entitlements Query Schema
class SubscriptionEntitlementsQuery(BaseModel):
    skus: Optional[List[str]] = Field(None, description="Filter to entitlements with the specified SKUs")

# Subscriptions Query Schema
class SubscriptionsQuery(BaseModel):
    perPage: Optional[int] = Field(1000, description="Number of entries per page")
    startingAfter: Optional[str] = Field(None, description="Starting token")
    endingBefore: Optional[str] = Field(None, description="Ending token")
    subscriptionIds: Optional[List[str]] = Field(None, description="List of subscription ids")
    organizationIds: List[str] = Field(..., description="Organizations to get subscriptions for")
    statuses: Optional[List[str]] = Field(None, description="List of statuses")
    productTypes: Optional[List[str]] = Field(None, description="List of product types")
    skus: Optional[List[str]] = Field(None, description="List of SKUs")
    name: Optional[str] = Field(None, description="Subscription name search")
    startDate: Optional[Union[str, dict]] = Field(None, description="Start date filter")
    endDate: Optional[Union[str, dict]] = Field(None, description="End date filter")

# Subscription Claim Schema
class SubscriptionClaimSchema(BaseModel):
    claimKey: str = Field(..., description="The subscription's claim key")
    organizationId: str = Field(..., description="The id of the organization claiming the subscription")
    name: Optional[str] = Field(None, description="Friendly name")
    description: Optional[str] = Field(None, description="Description")

# Subscription Claim Validate Schema
class SubscriptionClaimValidateSchema(BaseModel):
    claimKey: str = Field(..., description="The subscription's claim key")

# Subscription Compliance Statuses Query
class SubscriptionComplianceStatusesQuery(BaseModel):
    organizationIds: List[str] = Field(..., description="Organizations to get compliance for")
    subscriptionIds: Optional[List[str]] = Field(None, description="Subscription ids")

# Subscription Bind Schema
class SubscriptionBindSchema(BaseModel):
    networkIds: List[str] = Field(..., description="List of network ids to bind")

###################
# ERROR HANDLING DECORATOR
###################

def handle_meraki_errors(func: Callable) -> Callable:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except APIError as e:
            return json.dumps({
                "error": str(e),
                "status_code": e.status,
                "message": e.message
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "error": "Unexpected error",
                "message": str(e)
            }, indent=2)
    return wrapper

#######################
# ORGANIZATION TOOLS  #
#######################

@mcp.tool()
@handle_meraki_errors
async def get_organizations() -> str:
    """Get a list of organizations the user has access to"""
    organizations = await async_get_organizations()
    return json.dumps(organizations, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_organization_details(org_id: str = None) -> str:
    """Get details for a specific organization, defaults to the configured organization"""
    organization_id = org_id or MERAKI_ORG_ID
    org_details = await async_get_organization(organization_id)
    return json.dumps(org_details, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_networks(org_id: str = None) -> str:
    """Get a list of networks from Meraki"""
    organization_id = org_id or MERAKI_ORG_ID
    networks = await async_get_organization_networks(organization_id)
    return json.dumps(networks, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_devices(org_id: str = None) -> str:
    """Get a list of devices from Meraki"""
    organization_id = org_id or MERAKI_ORG_ID
    devices = await async_get_organization_devices(organization_id)
    return json.dumps(devices, indent=2)

@mcp.tool()
@handle_meraki_errors
async def create_network(name: str, tags: list[str], productTypes: list[str], org_id: str = None, copyFromNetworkId: str = None) -> str:
    """Create a new network in Meraki, optionally copying from another network."""
    organization_id = org_id or MERAKI_ORG_ID
    kwargs = {}
    if copyFromNetworkId:
        kwargs['copyFromNetworkId'] = copyFromNetworkId
    network = await async_create_network(organization_id, name, productTypes, tags=tags, **kwargs)
    return json.dumps(network, indent=2)

@mcp.tool()
@handle_meraki_errors
async def delete_network(network_id: str) -> str:
    """Delete a network in Meraki"""
    await async_delete_network(network_id)
    return f"Network {network_id} deleted"

@mcp.tool()
@handle_meraki_errors
async def get_organization_inventory(org_id: str = None) -> str:
    """Get the inventory for an organization"""
    organization_id = org_id or MERAKI_ORG_ID
    inventory = await async_get_organization_inventory(organization_id)
    return json.dumps(inventory, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_organization_license(org_id: str = None) -> str:
    """Get the license state for an organization"""
    organization_id = org_id or MERAKI_ORG_ID
    license_state = await async_get_organization_license(organization_id)
    return json.dumps(license_state, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_organization_conf_change(org_id: str = None) -> str:
    """Get the org change state for an organization"""
    organization_id = org_id or MERAKI_ORG_ID
    org_config_changes = await async_get_organization_conf_changes(organization_id)
    return json.dumps(org_config_changes, indent=2)

#######################
# NETWORK TOOLS       #
#######################

@mcp.tool()
@handle_meraki_errors
async def get_network_details(network_id: str) -> str:
    """Get details for a specific network"""
    network = await async_get_network(network_id)
    return json.dumps(network, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_network_devices(network_id: str) -> str:
    """Get a list of devices in a specific network"""
    devices = await async_get_network_devices(network_id)
    return json.dumps(devices, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_network(network_id: str, update_data: NetworkUpdateSchema) -> str:
    """
    Update a network's properties using a schema-validated model

    Args:
        network_id: The ID of the network to update
        update_data: Network properties to update (name, timeZone, tags, enrollmentString, notes)
    """
    # Convert the Pydantic model to a dictionary and filter out None values
    update_dict = {k: v for k, v in update_data.dict(exclude_none=True).items()}
    result = await to_async(dashboard.networks.updateNetwork)(network_id, **update_dict)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_clients(network_id: str, timespan: int = 86400) -> str:
    """
    Get a list of clients from a specific Meraki network.

    Args:
        network_id (str): The ID of the Meraki network.
        timespan (int): The timespan in seconds to get clients (default: 24 hours)

    Returns:
        str: JSON-formatted list of clients.
    """
    clients = await async_get_network_clients(network_id, timespan=timespan)
    return json.dumps(clients, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_client_details(network_id: str, client_id: str) -> str:
    """Get details for a specific client in a network"""
    client = await to_async(dashboard.networks.getNetworkClient)(network_id, client_id)
    return json.dumps(client, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_client_usage(network_id: str, client_id: str) -> str:
    """Get the usage history for a client"""
    usage = await to_async(dashboard.networks.getNetworkClientUsageHistory)(network_id, client_id)
    return json.dumps(usage, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_client_policy(network_id: str, client_id: str) -> str:
    """
    Get the policy for a specific client in a specific Meraki network.

    Args:
        network_id (str): The ID of the Meraki network.
        client_id (str): The ID (MAC address or client ID) of the client.

    Returns:
        str: JSON-formatted client policy.
    """
    policy = await to_async(dashboard.networks.getNetworkClientPolicy)(network_id, client_id)
    return json.dumps(policy, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_client_policy(network_id: str, client_id: str, device_policy: str, group_policy_id: str = None) -> str:
    """Update policy for a client"""
    kwargs = {'devicePolicy': device_policy}
    if group_policy_id:
        kwargs['groupPolicyId'] = group_policy_id

    result = await to_async(dashboard.networks.updateNetworkClientPolicy)(network_id, client_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_network_traffic(network_id: str, timespan: int = 86400) -> str:
    """Get traffic analysis data for a network"""
    traffic = await to_async(dashboard.networks.getNetworkTraffic)(network_id, timespan=timespan)
    return json.dumps(traffic, indent=2)

#######################
# DEVICE TOOLS        #
#######################

@mcp.tool()
@handle_meraki_errors
async def get_device_details(serial: str) -> str:
    """Get details for a specific device by serial number"""
    device = await async_get_device(serial)
    return json.dumps(device, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_device(serial: str, device_settings: DeviceUpdateSchema) -> str:
    """
    Update a device in the Meraki organization using a schema-validated model

    Args:
        serial: The serial number of the device to update
        device_settings: Device properties to update (name, tags, lat, lng, address, notes, etc.)

    Returns:
        Confirmation of the update with the new settings
    """
    # Convert the Pydantic model to a dictionary and filter out None values
    update_dict = {k: v for k, v in device_settings.dict(exclude_none=True).items()}

    updated_device = await async_update_device(serial, **update_dict)

    return json.dumps({
        "status": "success",
        "message": f"Device {serial} updated",
        "updated_settings": update_dict,
        "current_device": updated_device
    }, indent=2)

@mcp.tool()
@handle_meraki_errors
async def claim_devices(network_id: str, serials: list[str]) -> str:
    """Claim one or more devices into a Meraki network"""
    await to_async(dashboard.networks.claimNetworkDevices)(network_id, serials)
    return f"Devices {serials} claimed into network {network_id}"

@mcp.tool()
@handle_meraki_errors
async def remove_device(serial: str) -> str:
    """Remove a device from its network"""
    await to_async(dashboard.devices.removeNetworkDevices)(serial)
    return f"Device {serial} removed from network"

@mcp.tool()
@handle_meraki_errors
async def reboot_device(serial: str) -> str:
    """Reboot a device"""
    result = await to_async(dashboard.devices.rebootDevice)(serial)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_device_clients(serial: str, timespan: int = 86400) -> str:
    """Get clients connected to a specific device"""
    clients = await to_async(dashboard.devices.getDeviceClients)(serial, timespan=timespan)
    return json.dumps(clients, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_device_status(serial: str) -> str:
    """Get the current status of a device"""
    status = await to_async(dashboard.devices.getDeviceStatuses)(serial)
    return json.dumps(status, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_device_uplink(serial: str) -> str:
    """Get the uplink status of a device"""
    uplink = await to_async(dashboard.devices.getDeviceUplink)(serial)
    return json.dumps(uplink, indent=2)

#######################
# WIRELESS TOOLS      #
#######################

@mcp.tool()
@handle_meraki_errors
async def get_wireless_ssids(network_id: str) -> str:
    """Get wireless SSIDs for a network"""
    ssids = await async_get_wireless_ssids(network_id)
    return json.dumps(ssids, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_wireless_ssid(network_id: str, ssid_number: str, ssid_settings: SsidUpdateSchema) -> str:
    """
    Update a wireless SSID with comprehensive schema validation

    Args:
        network_id: The ID of the network containing the SSID
        ssid_number: The number of the SSID to update
        ssid_settings: Comprehensive SSID settings following the Meraki schema

    Returns:
        The updated SSID configuration
    """
    # Convert the Pydantic model to a dictionary and filter out None values
    update_dict = {k: v for k, v in ssid_settings.dict(exclude_none=True).items()}

    result = await async_update_wireless_ssid(network_id, ssid_number, **update_dict)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_wireless_settings(network_id: str) -> str:
    """Get wireless settings for a network"""
    settings = await to_async(dashboard.wireless.getNetworkWirelessSettings)(network_id)
    return json.dumps(settings, indent=2)

#######################
# SWITCH TOOLS        #
#######################

@mcp.tool()
@handle_meraki_errors
async def get_switch_ports(serial: str) -> str:
    """Get ports for a switch"""
    ports = await to_async(dashboard.switch.getDeviceSwitchPorts)(serial)
    return json.dumps(ports, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_switch_port(serial: str, port_id: str, name: str = None, tags: list[str] = None, enabled: bool = None, vlan: int = None) -> str:
    """Update a switch port"""
    kwargs = {}
    if name is not None:
        kwargs['name'] = name
    if tags is not None:
        kwargs['tags'] = tags
    if enabled is not None:
        kwargs['enabled'] = enabled
    if vlan is not None:
        kwargs['vlan'] = vlan

    result = await to_async(dashboard.switch.updateDeviceSwitchPort)(serial, port_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_switch_vlans(network_id: str) -> str:
    """Get VLANs for a network"""
    vlans = await to_async(dashboard.switch.getNetworkSwitchVlans)(network_id)
    return json.dumps(vlans, indent=2)

@mcp.tool()
@handle_meraki_errors
async def create_switch_vlan(network_id: str, vlan_id: int, name: str, subnet: str = None, appliance_ip: str = None) -> str:
    """Create a switch VLAN"""
    kwargs = {}
    if subnet is not None:
        kwargs['subnet'] = subnet
    if appliance_ip is not None:
        kwargs['applianceIp'] = appliance_ip

    result = await to_async(dashboard.switch.createNetworkSwitchVlan)(network_id, vlan_id, name, **kwargs)
    return json.dumps(result, indent=2)

#######################
# APPLIANCE TOOLS     #
#######################

@mcp.tool()
@handle_meraki_errors
async def get_security_center(network_id: str) -> str:
    """Get security information for a network"""
    security = await to_async(dashboard.appliance.getNetworkApplianceSecurityCenter)(network_id)
    return json.dumps(security, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_vpn_status(network_id: str) -> str:
    """Get VPN status for a network"""
    vpn_status = await to_async(dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn)(network_id)
    return json.dumps(vpn_status, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_firewall_rules(network_id: str) -> str:
    """Get firewall rules for a network"""
    rules = await to_async(dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules)(network_id)
    return json.dumps(rules, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_firewall_rules(network_id: str, rules: List[FirewallRule]) -> str:
    """
    Update firewall rules for a network using schema-validated models

    Args:
        network_id: The ID of the network
        rules: List of firewall rules following the Meraki schema

    Returns:
        The updated firewall rules configuration
    """
    # Convert the list of Pydantic models to a list of dictionaries
    rules_dict = [rule.dict(exclude_none=True) for rule in rules]

    result = await to_async(dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules)(network_id, rules=rules_dict)
    return json.dumps(result, indent=2)

#######################
# CAMERA TOOLS        #
#######################

@mcp.tool()
@handle_meraki_errors
async def get_camera_video_settings(network_id: str, serial: str) -> str:
    """Get video settings for a camera"""
    settings = await to_async(dashboard.camera.getDeviceCameraVideoSettings)(serial)
    return json.dumps(settings, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_camera_quality_settings(network_id: str) -> str:
    """Get quality and retention settings for cameras in a network"""
    settings = await to_async(dashboard.camera.getNetworkCameraQualityRetentionProfiles)(network_id)
    return json.dumps(settings, indent=2)

#######################
# ADVANCED ORGANIZATION TOOLS
#######################

@mcp.tool()
@handle_meraki_errors
async def get_organization_admins(org_id: str = None) -> str:
    """Get a list of organization admins"""
    organization_id = org_id or MERAKI_ORG_ID
    admins = await to_async(dashboard.organizations.getOrganizationAdmins)(organization_id)
    return json.dumps(admins, indent=2)

@mcp.tool()
@handle_meraki_errors
async def create_organization_admin(org_id: str, email: str, name: str, org_access: str, tags: list[str] = None, networks: list[dict] = None) -> str:
    """Create a new organization admin"""
    organization_id = org_id or MERAKI_ORG_ID
    kwargs = {
        'email': email,
        'name': name,
        'orgAccess': org_access
    }
    if tags is not None:
        kwargs['tags'] = tags
    if networks is not None:
        kwargs['networks'] = networks
    
    result = await to_async(dashboard.organizations.createOrganizationAdmin)(organization_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_organization_api_requests(org_id: str = None, timespan: int = 86400) -> str:
    """Get organization API request history"""
    organization_id = org_id or MERAKI_ORG_ID
    requests = await to_async(dashboard.organizations.getOrganizationApiRequests)(organization_id, timespan=timespan)
    return json.dumps(requests, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_organization_webhook_logs(org_id: str = None, timespan: int = 86400) -> str:
    """Get organization webhook logs"""
    organization_id = org_id or MERAKI_ORG_ID
    logs = await to_async(dashboard.organizations.getOrganizationWebhooksLogs)(organization_id, timespan=timespan)
    return json.dumps(logs, indent=2)

#######################
# ENHANCED NETWORK MONITORING
#######################

@mcp.tool()
@handle_meraki_errors
async def get_network_events(network_id: str, timespan: int = 86400, per_page: int = 100) -> str:
    """Get network events history"""
    events = await async_get_network_events(network_id, timespan=timespan, perPage=per_page)
    return json.dumps(events, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_network_event_types(network_id: str) -> str:
    """Get available network event types"""
    event_types = await async_get_network_event_types(network_id)
    return json.dumps(event_types, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_network_alerts_history(network_id: str, timespan: int = 86400) -> str:
    """Get network alerts history"""
    alerts = await async_get_network_alerts_history(network_id, timespan=timespan)
    return json.dumps(alerts, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_network_alerts_settings(network_id: str) -> str:
    """Get network alerts settings"""
    settings = await async_get_network_alerts_settings(network_id)
    return json.dumps(settings, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_network_alerts_settings(network_id: str, defaultDestinations: dict = None, alerts: list[dict] = None) -> str:
    """Update network alerts settings"""
    kwargs = {}
    if defaultDestinations is not None:
        kwargs['defaultDestinations'] = defaultDestinations
    if alerts is not None:
        kwargs['alerts'] = alerts
    
    result = await async_update_network_alerts_settings(network_id, **kwargs)
    return json.dumps(result, indent=2)

#######################
# LIVE DEVICE TOOLS
#######################

@mcp.tool()
@handle_meraki_errors
async def ping_device(serial: str, target_ip: str, count: int = 5) -> str:
    """Ping a device from another device"""
    result = await async_ping_device(serial, target_ip, count=count)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_device_ping_results(serial: str, ping_id: str) -> str:
    """Get results from a device ping test"""
    result = await async_get_device_ping_results(serial, ping_id)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def cable_test_device(serial: str, ports: list[str]) -> str:
    """Run cable test on device ports"""
    result = await async_cable_test_device(serial, ports)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_device_cable_test_results(serial: str, cable_test_id: str) -> str:
    """Get results from a device cable test"""
    result = await async_get_device_cable_test_results(serial, cable_test_id)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def blink_device_leds(serial: str, duration: int = 5) -> str:
    """Blink device LEDs for identification"""
    result = await async_blink_device_leds(serial, duration=duration)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def wake_on_lan_device(serial: str, mac: str) -> str:
    """Send wake-on-LAN packet to a device"""
    result = await async_wake_on_lan_device(serial, mac)
    return json.dumps(result, indent=2)

#######################
# ADVANCED WIRELESS TOOLS
#######################

@mcp.tool()
@handle_meraki_errors
async def get_wireless_rf_profiles(network_id: str) -> str:
    """Get wireless RF profiles for a network"""
    profiles = await async_get_wireless_rf_profiles(network_id)
    return json.dumps(profiles, indent=2)

@mcp.tool()
@handle_meraki_errors
async def create_wireless_rf_profile(network_id: str, name: str, band_selection_type: str, **kwargs) -> str:
    """Create a wireless RF profile"""
    result = await async_create_wireless_rf_profile(network_id, name, bandSelectionType=band_selection_type, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_wireless_channel_utilization(network_id: str, timespan: int = 86400) -> str:
    """Get wireless channel utilization history"""
    utilization = await async_get_wireless_channel_utilization(network_id, timespan=timespan)
    return json.dumps(utilization, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_wireless_signal_quality(network_id: str, timespan: int = 86400) -> str:
    """Get wireless signal quality history"""
    quality = await async_get_wireless_signal_quality(network_id, timespan=timespan)
    return json.dumps(quality, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_wireless_connection_stats(network_id: str, timespan: int = 86400) -> str:
    """Get wireless connection statistics"""
    stats = await async_get_wireless_connection_stats(network_id, timespan=timespan)
    return json.dumps(stats, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_wireless_client_connectivity_events(network_id: str, client_id: str, timespan: int = 86400) -> str:
    """Get wireless client connectivity events"""
    events = await async_get_wireless_client_connectivity_events(network_id, client_id, timespan=timespan)
    return json.dumps(events, indent=2)

#######################
# ADVANCED SWITCH TOOLS
#######################

@mcp.tool()
@handle_meraki_errors
async def get_switch_port_statuses(serial: str) -> str:
    """Get switch port statuses"""
    statuses = await async_get_switch_port_statuses(serial)
    return json.dumps(statuses, indent=2)

@mcp.tool()
@handle_meraki_errors
async def cycle_switch_ports(serial: str, ports: list[str]) -> str:
    """Cycle (restart) switch ports"""
    result = await async_cycle_switch_ports(serial, ports)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_switch_access_control_lists(network_id: str) -> str:
    """Get switch access control lists"""
    acls = await async_get_switch_access_control_lists(network_id)
    return json.dumps(acls, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_switch_access_control_lists(network_id: str, rules: list[dict]) -> str:
    """Update switch access control lists"""
    result = await async_update_switch_access_control_lists(network_id, rules)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_switch_qos_rules(network_id: str) -> str:
    """Get switch QoS rules"""
    rules = await async_get_switch_qos_rules(network_id)
    return json.dumps(rules, indent=2)

@mcp.tool()
@handle_meraki_errors
async def create_switch_qos_rule(network_id: str, vlan: int, protocol: str, src_port: int, src_port_range: str = None, dst_port: int = None, dst_port_range: str = None, dscp: int = None) -> str:
    """Create a switch QoS rule"""
    kwargs = {
        'vlan': vlan,
        'protocol': protocol,
        'srcPort': src_port
    }
    if src_port_range is not None:
        kwargs['srcPortRange'] = src_port_range
    if dst_port is not None:
        kwargs['dstPort'] = dst_port
    if dst_port_range is not None:
        kwargs['dstPortRange'] = dst_port_range
    if dscp is not None:
        kwargs['dscp'] = dscp
    
    result = await async_create_switch_qos_rule(network_id, **kwargs)
    return json.dumps(result, indent=2)

#######################
# ADVANCED APPLIANCE TOOLS
#######################

@mcp.tool()
@handle_meraki_errors
async def get_appliance_vpn_site_to_site(network_id: str) -> str:
    """Get appliance VPN site-to-site configuration"""
    vpn = await async_get_appliance_vpn_site_to_site(network_id)
    return json.dumps(vpn, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_appliance_vpn_site_to_site(network_id: str, mode: str, hubs: list[dict] = None, subnets: list[dict] = None) -> str:
    """Update appliance VPN site-to-site configuration"""
    kwargs = {'mode': mode}
    if hubs is not None:
        kwargs['hubs'] = hubs
    if subnets is not None:
        kwargs['subnets'] = subnets
    
    result = await async_update_appliance_vpn_site_to_site(network_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_appliance_content_filtering(network_id: str) -> str:
    """Get appliance content filtering settings"""
    filtering = await async_get_appliance_content_filtering(network_id)
    return json.dumps(filtering, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_appliance_content_filtering(network_id: str, allowed_urls: list[str] = None, blocked_urls: list[str] = None, blocked_url_patterns: list[str] = None, youtube_restricted_for_teenagers: bool = None, youtube_restricted_for_mature: bool = None) -> str:
    """Update appliance content filtering settings"""
    kwargs = {}
    if allowed_urls is not None:
        kwargs['allowedUrls'] = allowed_urls
    if blocked_urls is not None:
        kwargs['blockedUrls'] = blocked_urls
    if blocked_url_patterns is not None:
        kwargs['blockedUrlPatterns'] = blocked_url_patterns
    if youtube_restricted_for_teenagers is not None:
        kwargs['youtubeRestrictedForTeenagers'] = youtube_restricted_for_teenagers
    if youtube_restricted_for_mature is not None:
        kwargs['youtubeRestrictedForMature'] = youtube_restricted_for_mature
    
    result = await async_update_appliance_content_filtering(network_id, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_appliance_security_events(network_id: str, timespan: int = 86400) -> str:
    """Get appliance security events"""
    events = await async_get_appliance_security_events(network_id, timespan=timespan)
    return json.dumps(events, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_appliance_traffic_shaping(network_id: str) -> str:
    """Get appliance traffic shaping settings"""
    shaping = await async_get_appliance_traffic_shaping(network_id)
    return json.dumps(shaping, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_appliance_traffic_shaping(network_id: str, global_bandwidth_limits: dict = None) -> str:
    """Update appliance traffic shaping settings"""
    kwargs = {}
    if global_bandwidth_limits is not None:
        kwargs['globalBandwidthLimits'] = global_bandwidth_limits
    
    result = await async_update_appliance_traffic_shaping(network_id, **kwargs)
    return json.dumps(result, indent=2)

#######################
# CAMERA TOOLS
#######################

@mcp.tool()
@handle_meraki_errors
async def get_camera_analytics_live(serial: str) -> str:
    """Get live camera analytics"""
    analytics = await async_get_camera_analytics_live(serial)
    return json.dumps(analytics, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_camera_analytics_overview(serial: str, timespan: int = 86400) -> str:
    """Get camera analytics overview"""
    overview = await async_get_camera_analytics_overview(serial, timespan=timespan)
    return json.dumps(overview, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_camera_analytics_zones(serial: str) -> str:
    """Get camera analytics zones"""
    zones = await async_get_camera_analytics_zones(serial)
    return json.dumps(zones, indent=2)

@mcp.tool()
@handle_meraki_errors
async def generate_camera_snapshot(serial: str, timestamp: str = None) -> str:
    """Generate a camera snapshot"""
    kwargs = {}
    if timestamp is not None:
        kwargs['timestamp'] = timestamp
    
    result = await async_generate_camera_snapshot(serial, **kwargs)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_camera_sense(serial: str) -> str:
    """Get camera sense configuration"""
    sense = await async_get_camera_sense(serial)
    return json.dumps(sense, indent=2)

@mcp.tool()
@handle_meraki_errors
async def update_camera_sense(serial: str, sense_enabled: bool = None, mqtt_broker_id: str = None, audio_detection: dict = None) -> str:
    """Update camera sense configuration"""
    kwargs = {}
    if sense_enabled is not None:
        kwargs['senseEnabled'] = sense_enabled
    if mqtt_broker_id is not None:
        kwargs['mqttBrokerId'] = mqtt_broker_id
    if audio_detection is not None:
        kwargs['audioDetection'] = audio_detection
    
    result = await async_update_camera_sense(serial, **kwargs)
    return json.dumps(result, indent=2)

#######################
# NETWORK AUTOMATION TOOLS
#######################

@mcp.tool()
@handle_meraki_errors
async def create_action_batch(org_id: str, actions: list[dict], confirmed: bool = True, synchronous: bool = False) -> str:
    """Create an action batch for bulk operations"""
    organization_id = org_id or MERAKI_ORG_ID
    result = await async_create_action_batch(organization_id, actions, confirmed=confirmed, synchronous=synchronous)
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_action_batch_status(org_id: str, batch_id: str) -> str:
    """Get action batch status"""
    organization_id = org_id or MERAKI_ORG_ID
    status = await async_get_action_batch_status(organization_id, batch_id)
    return json.dumps(status, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_action_batches(org_id: str = None) -> str:
    """Get all action batches for an organization"""
    organization_id = org_id or MERAKI_ORG_ID
    batches = await async_get_action_batches(organization_id)
    return json.dumps(batches, indent=2)

#######################
# NEW TOOLS FROM SPEC
#######################

@mcp.tool()
@handle_meraki_errors
async def get_administered_identities_me() -> str:
    """Returns the identity of the current user."""
    result = await async_get_administered_identities_me()
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def get_administered_identities_me_api_keys() -> str:
    """List the non-sensitive metadata associated with the API keys that belong to the user"""
    result = await async_get_administered_identities_me_api_keys()
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def generate_administered_identities_me_api_keys() -> str:
    """Generates an API key for an identity"""
    result = await async_generate_administered_identities_me_api_keys()
    return json.dumps(result, indent=2)

@mcp.tool()
@handle_meraki_errors
async def revoke_administered_identities_me_api_keys(suffix: str) -> str:
    """Revokes an identity's API key, using the last four characters of the key"""
    result = await async_revoke_administered_identities_me_api_keys(suffix)
    return json.dumps(result, indent=2)

# Add a dynamic greeting resource
@mcp.resource("greeting: //{name}")
def greeting(name: str) -> str:
    """Greet a user by name"""
    return f"Hello {name}!"

# execute and return the stdio output
if __name__ == "__main__":
    mcp.run()