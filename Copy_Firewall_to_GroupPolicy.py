import os
import re
import ipaddress
import meraki
from dotenv import load_dotenv

# Load environment variables

# Must have environment variables with the below information stored.
load_dotenv()
API_KEY = os.getenv('MERAKI_API_KEY')
ORG_ID = os.getenv('MERAKI_ORG_ID')
NETWORK_ID = os.getenv('MERAKI_NETWORK_ID')
GROUP_POLICY_NAME = 'TEST_GP' # Modify this name as needed

dashboard = meraki.DashboardAPI(API_KEY, print_console=False)

# === Load data ===

# get 
def get_l3_firewall_rules(network_id):
    try:
        response = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
        return response.get('rules', [])
    except Exception as e:
        print(f" Failed to fetch L3 firewall rules: {e}")
        return []
    
def get_l7_firewall_rules(network_id):
    try:
        response = dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules(network_id)
        rules = response.get('rules', [])
        filtered = []
        dropped = 0

        for rule in rules:
            if 'blockedCountries' in rule:
                dropped += 1
                continue  # Drop unsupported country rule. Group Policy does support countries, but the API is currently unable to handle them. They must set them up afterwards.
            filtered.append(rule)

        if dropped:
            print(f" Dropped {dropped} unsupported country-based L7 rule(s).")
        return filtered
    except Exception as e:
        print(f" Failed to fetch L7 firewall rules: {e}")
        return []



# Group policies won't take VLAN Objects, so this is needed to bust them out into a CIDR format
def get_vlan_map(network_id):
    vlan_map = {}
    try:
        vlans = dashboard.appliance.getNetworkApplianceVlans(NETWORK_ID)
        for vlan in vlans:
            vlan_id = str(vlan['id'])
            if 'subnet' in vlan:
                vlan_map[vlan_id] = vlan['subnet']
    except Exception as e:
        print(f" Failed to fetch VLANs: {e}")
    return vlan_map

# Group policies won't take object IDs, so this is needed to bust them out into CIDR formats
def get_policy_objects_map(org_id):
    obj_map = {}
    try:
        objects = dashboard.organizations.getOrganizationPolicyObjects(org_id)
        obj_map = {obj['id']: obj['cidr'] for obj in objects if obj.get('type') == 'cidr'}
    except Exception as e:
        print(f" Failed to fetch policy objects: {e}")
    return obj_map


def get_group_objects_map(org_id):
    group_map = {}
    try:
        groups = dashboard.organizations.getOrganizationPolicyObjectsGroups(org_id)
        for group in groups:
            group_id = group['id']
            group_map[group_id] = group.get('objectIds', [])
    except Exception as e:
        print(f" Failed to fetch object groups: {e}")
    return group_map

# === Resolve VLAN/OBJ/GRP references ===

def resolve_meraki_references_in_rules(rules, vlan_map, object_map, group_map):
    resolved_rules = []

    for rule in rules:
        new_rule = rule.copy()

        for key in ['srcCidr', 'destCidr']:
            original = new_rule.get(key, '')
            cidr_list = []

            # Lowercase 'any'
            if original.lower() == 'any':
                new_rule[key] = 'any'
                continue

            parts = [part.strip() for part in original.split(',')]
            for part in parts:
                vlan_match = re.match(r'VLAN\((\d+)\)', part.split('.')[0])

                obj_match = re.match(r'OBJ\((\d+)\)', part)
                grp_match = re.match(r'GRP\((\d+)\)', part)

                if vlan_match:
                    vlan_id = vlan_match.group(1)
                    cidr = vlan_map.get(vlan_id)
                    if cidr:
                        cidr_list.append(cidr)
                    else:
                        print(f" Could not resolve VLAN({vlan_id})")
                elif obj_match:
                    obj_id = obj_match.group(1)
                    cidr = object_map.get(obj_id)
                    if cidr:
                        cidr_list.append(cidr)
                    else:
                        print(f" Could not resolve OBJ({obj_id})")
                elif grp_match:
                    grp_id = grp_match.group(1)
                    object_ids = group_map.get(grp_id, [])
                    for oid in object_ids:
                        cidr = object_map.get(oid)
                        if cidr:
                            cidr_list.append(cidr)
                        else:
                            print(f" GRP({grp_id}) has unresolved OBJ({oid})")
                else:
                    print(f" Unrecognized/unsupported pattern: {part}")

            if cidr_list:
                new_rule[key] = ','.join(cidr_list)
            else:
                print(f" Skipping rule due to unresolved {key}: {original}")
                break  # skip this rule entirely
        else:
            resolved_rules.append(new_rule)

    return resolved_rules

# === Validate & sanitize rules ===

def sanitize_rules(rules):
    valid_rules = []

    for rule in rules:
        def is_valid_cidr(cidr):
            if cidr == 'any':
                return True
            try:
                ipaddress.ip_network(cidr, strict=False)
                return True
            except ValueError:
                return False

        srcs = rule.get('srcCidr', '').split(',')
        dests = rule.get('destCidr', '').split(',')

        # Split into 1:1 rule copies
        for src in srcs:
            for dest in dests:
                src = src.strip().lower()
                dest = dest.strip().lower()

                if is_valid_cidr(src) and is_valid_cidr(dest):
                    new_rule = rule.copy()
                    new_rule['srcCidr'] = src
                    new_rule['destCidr'] = dest
                    valid_rules.append(new_rule)
                else:
                    print(f" Invalid CIDR pair: src={src}, dest={dest}. Rule skipped.")

    return valid_rules

# === Create Group Policy ===

def create_group_policy_with_rules(network_id, name, l3_rules, l7_rules):
    print(f" Creating group policy '{name}' with {len(l3_rules)} L3 rule(s) and {len(l7_rules)} L7 rule(s)...")
    try:
        return dashboard.networks.createNetworkGroupPolicy(
            network_id,
            name=name,
            scheduling={'enabled': False},
            bandwidth={'settings': 'network default'},
            firewallAndTrafficShaping={
                'settings': 'custom',
                'l3FirewallRules': l3_rules,
                'trafficShapingRules': [],
                'l7FirewallRules': l7_rules,
                'contentFiltering': {
                    'allowedUrlPatterns': [],
                    'blockedUrlPatterns': [],
                    'blockedUrlCategories': []
                }
            }
        )
    except Exception as e:
        print(f" Failed to create group policy: {e}")
        return None

# === Main ===

if __name__ == '__main__':
    print(f" Network ID: {NETWORK_ID}")

    vlan_map = get_vlan_map(NETWORK_ID)
    object_map = get_policy_objects_map(ORG_ID)
    group_map = get_group_objects_map(ORG_ID)

    raw_rules = get_l3_firewall_rules(NETWORK_ID)

    resolved_rules = resolve_meraki_references_in_rules(raw_rules, vlan_map, object_map, group_map)
    cleaned_rules = sanitize_rules(resolved_rules)

    #  Grab L7 rules here
    l7_rules = get_l7_firewall_rules(NETWORK_ID)

    #  Print for sanity check (optional)
    import json
    print(" L7 Rules:")
    print(json.dumps(l7_rules, indent=2))

    #  Create the Group Policy using L3 + L7
    if cleaned_rules:
        gp = create_group_policy_with_rules(NETWORK_ID, GROUP_POLICY_NAME, cleaned_rules, l7_rules)
        if gp:
            print(f" Group Policy '{gp['name']}' created successfully. ID: {gp['groupPolicyId']}")
    else:
        print(" No valid L3 rules to apply. Group policy not created.")
