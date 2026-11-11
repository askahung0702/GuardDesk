"""Merge typed publisher denials with the existing local application policy."""
import copy
import uuid
import xml.etree.ElementTree as ET
from .application_control import applocker_xml,NAMESPACE
from .custom_settings import validate,DEFAULT
from .policy import DEFAULT_POLICY

def publisher_xml(control,rules):
    validate({**copy.deepcopy(DEFAULT),'software':rules})
    # Disabled legacy allowlists/latent rules must not become active merely
    # because the administrator adds one custom product denial.
    base=control if control['enabled'] else copy.deepcopy(DEFAULT_POLICY['application_control'])
    if rules and base['enabled'] and base['mode']=='denylist' and not base['rules'] and not base['block_msi']:
        base={**base,'enabled':False}
    root=ET.fromstring(applocker_xml(base))
    for rule in rules:
        kind=rule['collection'];collection=root.find("RuleCollection[@Type='"+kind+"']")
        if collection is None:
            collection=ET.SubElement(root,'RuleCollection',Type=kind,EnforcementMode='Enabled')
            allow=ET.SubElement(collection,'FilePublisherRule',Id=str(uuid.uuid5(NAMESPACE,'custom-appx-default-allow')),Name='GuardDesk: signed packaged apps',Description='Keep unrelated packaged apps allowed',UserOrGroupSid='S-1-1-0',Action='Allow')
            condition=ET.SubElement(ET.SubElement(allow,'Conditions'),'FilePublisherCondition',PublisherName='*',ProductName='*',BinaryName='*')
            ET.SubElement(condition,'BinaryVersionRange',LowSection='0.0.0.0',HighSection='*')
        identity='|'.join(str(rule[k]) for k in sorted(rule))
        node=ET.SubElement(collection,'FilePublisherRule',Id=str(uuid.uuid5(NAMESPACE,'custom|'+identity)),Name='GuardDesk: '+rule['name'],Description='Custom settings product denial',UserOrGroupSid='S-1-1-0',Action='Deny')
        condition=ET.SubElement(ET.SubElement(node,'Conditions'),'FilePublisherCondition',PublisherName=rule['publisher'],ProductName=rule['product'],BinaryName=rule['binary'])
        ET.SubElement(condition,'BinaryVersionRange',LowSection=rule['min_version'],HighSection=rule['max_version'])
    return ET.tostring(root,encoding='unicode')
