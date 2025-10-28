# Meraki Magic MCP

Meraki Magic is a Python-based MCP (Model Context Protocol) server for Cisco's Meraki Dashboard. Meraki Magic provides tools for querying the Meraki Dashboard API to discover, monitor, and manage your Meraki environment.

## Features

- **Comprehensive Network Management**: Full network discovery, monitoring, and management
- **Advanced Device Management**: Device provisioning, monitoring, and live tools
- **Wireless Management**: Complete wireless SSID and RF profile management
- **Switch Management**: Port management, VLAN configuration, and QoS rules
- **Appliance Management**: VPN, firewall, content filtering, and security management
- **Camera Management**: Analytics, snapshots, and sense configuration
- **Network Automation**: Action batches and bulk operations
- **Live Device Tools**: Ping, cable testing, LED control, and wake-on-LAN
- **Advanced Monitoring**: Events, alerts, and performance analytics

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mkutka/meraki-magic.git
cd meraki-magic-mcp
```

2. Create a virtual environment and activate it:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

1. Copy the example environment file:
```bash
cp .env-example .env
```

2. Update the `.env` file with your Meraki API Key and Organization ID:
```env
MERAKI_API_KEY="Meraki API Key here"
MERAKI_ORG_ID="Meraki Org ID here"
```

## Usage With Claude Desktop Client

1. Configure Claude Desktop to use this MCP server:

- Open Claude Desktop
- Go to Settings > Developer > Edit Config
- Add the following configuration file `claude_desktop_config.json`

```json
{
  "mcpServers": {
      "Meraki_Magic_MCP": {
        "command": "/Users/mkutka/meraki-magic-mcp/.venv/bin/fastmcp",
        "args": [
          "run",
          "/Users/mkutka/meraki-magic-mcp/meraki-mcp.py"
        ]
      }
  }
}
```

- Replace the paths above to reflect your local environment.

2. Restart Claude Desktop

3. Interact with Claude Desktop

## Network Tools Guide

This guide provides a comprehensive overview of all the network tools available in the Meraki Magic MCP, organized by category and functionality.

### Table of Contents

1. [Organization Management Tools](#organization-management-tools)
2. [Network Management Tools](#network-management-tools)
3. [Device Management Tools](#device-management-tools)
4. [Wireless Management Tools](#wireless-management-tools)
5. [Switch Management Tools](#switch-management-tools)
6. [Appliance Management Tools](#appliance-management-tools)
7. [Camera Management Tools](#camera-management-tools)
8. [Network Automation Tools](#network-automation-tools)
9. [Advanced Monitoring Tools](#advanced-monitoring-tools)
10. [Live Device Tools](#live-device-tools)

---

## Organization Management Tools

### Basic Organization Operations
- **`get_organizations()`** - Get a list of organizations the user has access to
- **`get_organization_details(org_id)`** - Get details for a specific organization
- **`get_organization_status(org_id)`** - Get the status and health of an organization
- **`get_organization_inventory(org_id)`** - Get the inventory for an organization
- **`get_organization_license(org_id)`** - Get the license state for an organization
- **`get_organization_conf_change(org_id)`** - Get the org change state for an organization

### Advanced Organization Management
- **`get_organization_admins(org_id)`** - Get a list of organization admins
- **`create_organization_admin(org_id, email, name, org_access, tags, networks)`** - Create a new organization admin
- **`get_organization_api_requests(org_id, timespan)`** - Get organization API request history
- **`get_organization_webhook_logs(org_id, timespan)`** - Get organization webhook logs

### Network Management
- **`get_networks(org_id)`** - Get a list of networks from Meraki
- **`create_network(name, tags, productTypes, org_id, copyFromNetworkId)`** - Create a new network
- **`delete_network(network_id)`** - Delete a network in Meraki
- **`get_network_details(network_id)`** - Get details for a specific network
- **`update_network(network_id, update_data)`** - Update a network's properties

---

## Network Management Tools

### Network Monitoring
- **`get_network_events(network_id, timespan, per_page)`** - Get network events history
- **`get_network_event_types(network_id)`** - Get available network event types
- **`get_network_alerts_history(network_id, timespan)`** - Get network alerts history
- **`get_network_alerts_settings(network_id)`** - Get network alerts settings
- **`update_network_alerts_settings(network_id, defaultDestinations, alerts)`** - Update network alerts settings

### Client Management
- **`get_clients(network_id, timespan)`** - Get a list of clients from a network
- **`get_client_details(network_id, client_id)`** - Get details for a specific client
- **`get_client_usage(network_id, client_id)`** - Get the usage history for a client
- **`get_client_policy(network_id, client_id)`** - Get the policy for a specific client
- **`update_client_policy(network_id, client_id, device_policy, group_policy_id)`** - Update policy for a client

### Network Traffic & Analysis
- **`get_network_traffic(network_id, timespan)`** - Get traffic analysis data for a network

---

## Device Management Tools

### Device Information
- **`get_devices(org_id)`** - Get a list of devices from Meraki
- **`get_network_devices(network_id)`** - Get a list of devices in a specific network
- **`get_device_details(serial)`** - Get details for a specific device by serial number
- **`get_device_status(serial)`** - Get the current status of a device
- **`get_device_uplink(serial)`** - Get the uplink status of a device

### Device Operations
- **`update_device(serial, device_settings)`** - Update a device in the Meraki organization
- **`claim_devices(network_id, serials)`** - Claim one or more devices into a Meraki network
- **`remove_device(serial)`** - Remove a device from its network
- **`reboot_device(serial)`** - Reboot a device

### Device Monitoring
- **`get_device_clients(serial, timespan)`** - Get clients connected to a specific device

---

## Live Device Tools

### Network Diagnostics
- **`ping_device(serial, target_ip, count)`** - Ping a device from another device
- **`get_device_ping_results(serial, ping_id)`** - Get results from a device ping test
- **`cable_test_device(serial, ports)`** - Run cable test on device ports
- **`get_device_cable_test_results(serial, cable_test_id)`** - Get results from a device cable test

### Device Control
- **`blink_device_leds(serial, duration)`** - Blink device LEDs for identification
- **`wake_on_lan_device(serial, mac)`** - Send wake-on-LAN packet to a device

---

## Wireless Management Tools

### Basic Wireless Operations
- **`get_wireless_ssids(network_id)`** - Get wireless SSIDs for a network
- **`update_wireless_ssid(network_id, ssid_number, ssid_settings)`** - Update a wireless SSID
- **`get_wireless_settings(network_id)`** - Get wireless settings for a network

### Advanced Wireless Management
- **`get_wireless_rf_profiles(network_id)`** - Get wireless RF profiles for a network
- **`create_wireless_rf_profile(network_id, name, band_selection_type, **kwargs)`** - Create a wireless RF profile
- **`get_wireless_channel_utilization(network_id, timespan)`** - Get wireless channel utilization history
- **`get_wireless_signal_quality(network_id, timespan)`** - Get wireless signal quality history
- **`get_wireless_connection_stats(network_id, timespan)`** - Get wireless connection statistics
- **`get_wireless_client_connectivity_events(network_id, client_id, timespan)`** - Get wireless client connectivity events

---

## Switch Management Tools

### Basic Switch Operations
- **`get_switch_ports(serial)`** - Get ports for a switch
- **`update_switch_port(serial, port_id, name, tags, enabled, vlan)`** - Update a switch port
- **`get_switch_vlans(network_id)`** - Get VLANs for a network
- **`create_switch_vlan(network_id, vlan_id, name, subnet, appliance_ip)`** - Create a switch VLAN

### Advanced Switch Management
- **`get_switch_port_statuses(serial)`** - Get switch port statuses
- **`cycle_switch_ports(serial, ports)`** - Cycle (restart) switch ports
- **`get_switch_access_control_lists(network_id)`** - Get switch access control lists
- **`update_switch_access_control_lists(network_id, rules)`** - Update switch access control lists
- **`get_switch_qos_rules(network_id)`** - Get switch QoS rules
- **`create_switch_qos_rule(network_id, vlan, protocol, src_port, **kwargs)`** - Create a switch QoS rule

---

## Appliance Management Tools

### Basic Appliance Operations
- **`get_security_center(network_id)`** - Get security information for a network
- **`get_vpn_status(network_id)`** - Get VPN status for a network
- **`get_firewall_rules(network_id)`** - Get firewall rules for a network
- **`update_firewall_rules(network_id, rules)`** - Update firewall rules for a network

### Advanced Appliance Management
- **`get_appliance_vpn_site_to_site(network_id)`** - Get appliance VPN site-to-site configuration
- **`update_appliance_vpn_site_to_site(network_id, mode, hubs, subnets)`** - Update appliance VPN site-to-site configuration
- **`get_appliance_content_filtering(network_id)`** - Get appliance content filtering settings
- **`update_appliance_content_filtering(network_id, **kwargs)`** - Update appliance content filtering settings
- **`get_appliance_security_events(network_id, timespan)`** - Get appliance security events
- **`get_appliance_traffic_shaping(network_id)`** - Get appliance traffic shaping settings
- **`update_appliance_traffic_shaping(network_id, global_bandwidth_limits)`** - Update appliance traffic shaping settings

---

## Camera Management Tools

### Basic Camera Operations
- **`get_camera_video_settings(network_id, serial)`** - Get video settings for a camera
- **`get_camera_quality_settings(network_id)`** - Get quality and retention settings for cameras

### Advanced Camera Management
- **`get_camera_analytics_live(serial)`** - Get live camera analytics
- **`get_camera_analytics_overview(serial, timespan)`** - Get camera analytics overview
- **`get_camera_analytics_zones(serial)`** - Get camera analytics zones
- **`generate_camera_snapshot(serial, timestamp)`** - Generate a camera snapshot
- **`get_camera_sense(serial)`** - Get camera sense configuration
- **`update_camera_sense(serial, sense_enabled, mqtt_broker_id, audio_detection)`** - Update camera sense configuration

---

## Network Automation Tools

### Action Batches
- **`create_action_batch(org_id, actions, confirmed, synchronous)`** - Create an action batch for bulk operations
- **`get_action_batch_status(org_id, batch_id)`** - Get action batch status
- **`get_action_batches(org_id)`** - Get all action batches for an organization

---

## Advanced Monitoring Tools

### Network Events & Alerts
- **`get_network_events(network_id, timespan, per_page)`** - Get network events history
- **`get_network_event_types(network_id)`** - Get available network event types
- **`get_network_alerts_history(network_id, timespan)`** - Get network alerts history
- **`get_network_alerts_settings(network_id)`** - Get network alerts settings
- **`update_network_alerts_settings(network_id, defaultDestinations, alerts)`** - Update network alerts settings

### Organization Monitoring
- **`get_organization_api_requests(org_id, timespan)`** - Get organization API request history
- **`get_organization_webhook_logs(org_id, timespan)`** - Get organization webhook logs

---

## Schema Definitions

The MCP includes comprehensive Pydantic schemas for data validation:

- `SsidUpdateSchema` - Wireless SSID configuration
- `FirewallRule` - Firewall rule configuration
- `DeviceUpdateSchema` - Device update parameters
- `NetworkUpdateSchema` - Network update parameters
- `AdminCreationSchema` - Admin creation parameters
- `ActionBatchSchema` - Action batch configuration
- `VpnSiteToSiteSchema` - VPN site-to-site configuration
- `ContentFilteringSchema` - Content filtering settings
- `TrafficShapingSchema` - Traffic shaping configuration
- `CameraSenseSchema` - Camera sense settings
- `SwitchQosRuleSchema` - Switch QoS rule configuration

---

## Best Practices

1. **Error Handling**: Always check API responses for errors
2. **Rate Limiting**: The Meraki API has rate limits; use appropriate delays
3. **Batch Operations**: Use action batches for bulk operations
4. **Validation**: Use the provided schemas for data validation
5. **Monitoring**: Regularly check network events and alerts
6. **Security**: Keep API keys secure and rotate them regularly

---

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Verify your API key is correct and has appropriate permissions
2. **Rate Limiting**: If you encounter rate limiting, implement delays between requests
3. **Network Not Found**: Ensure the network ID is correct and accessible
4. **Device Not Found**: Verify the device serial number is correct and the device is online

### Debug Information

Enable debug logging by setting the appropriate log level in your environment.

---

## Additional Resources

- [Meraki API Documentation](https://developer.cisco.com/meraki/api-v1/)
- [MCP Protocol Documentation](https://modelcontextprotocol.io/)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)

For more detailed information about additional tools and future enhancements, see the [Additional Tools Roadmap](ADDITIONAL_TOOLS_ROADMAP.md).

---

## ⚠️ Disclaimer

**IMPORTANT: PRODUCTION USE DISCLAIMER**

This software is provided "AS IS" without warranty of any kind, either express or implied. The authors and contributors make no representations or warranties regarding the suitability, reliability, availability, accuracy, or completeness of this software for any purpose.

**USE AT YOUR OWN RISK**: This MCP server is designed for development, testing, and educational purposes. Running this software in production environments is done entirely at your own risk. The authors and contributors are not responsible for any damages, data loss, service interruptions, or other issues that may arise from the use of this software in production environments.

**SECURITY CONSIDERATIONS**: This software requires access to your Meraki API credentials. Ensure that:
- API keys are stored securely and not committed to version control
- API keys have appropriate permissions and are rotated regularly
- Network access is properly secured
- Regular security audits are performed

**NO WARRANTY**: The authors disclaim all warranties, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors be liable for any claim, damages, or other liability arising from the use of this software.

**SUPPORT**: This is an open-source project. For production use, consider implementing additional testing, monitoring, and support mechanisms appropriate for your environment.