#!/usr/bin/env python3
"""
MITRE ATT&CK Data Extraction Script

This script processes MITRE ATT&CK JSON files from enterprise-attack, ics-attack, and mobile-attack
folders and extracts comprehensive technique information into consolidated JSON files.
"""

import json
import os
import glob
from typing import Dict, List, Any, Optional
from collections import defaultdict

def extract_technique_id(external_refs: List[Dict]) -> Optional[str]:
    """Extract the MITRE ATT&CK technique ID from external references."""
    for ref in external_refs:
        if ref.get('source_name') == 'mitre-attack' and 'external_id' in ref:
            return ref['external_id']
    return None

def extract_tactics(kill_chain_phases: List[Dict]) -> List[str]:
    """Extract tactic names from kill chain phases."""
    tactics = []
    for phase in kill_chain_phases:
        if phase.get('kill_chain_name') == 'mitre-attack':
            tactic = phase.get('phase_name', '').replace('-', ' ').title()
            if tactic:
                tactics.append(tactic)
    return tactics

def extract_external_references(external_refs: List[Dict]) -> List[Dict]:
    """Extract and format external references."""
    references = []
    for ref in external_refs:
        if ref.get('source_name') != 'mitre-attack':  # Skip the MITRE ATT&CK reference
            ref_data = {
                'source_name': ref.get('source_name', ''),
                'description': ref.get('description', ''),
                'url': ref.get('url', '')
            }
            references.append(ref_data)
    return references

def find_relationships(technique_id: str, relationships: List[Dict], 
                      mitigations: Dict, groups: Dict, software: Dict) -> Dict:
    """Find relationships for a technique including mitigations, groups, and software."""
    result = {
        'mitigations': [],
        'groups': [],
        'software': []
    }
    
    for rel in relationships:
        if rel.get('target_ref', '').startswith('attack-pattern--'):
            # Find relationships where this technique is the target
            source_ref = rel.get('source_ref', '')
            relationship_type = rel.get('relationship_type', '')
            
            if relationship_type == 'mitigates' and source_ref in mitigations:
                mitigation = mitigations[source_ref]
                result['mitigations'].append({
                    'name': mitigation.get('name', ''),
                    'description': mitigation.get('description', '')[:200] + '...' if len(mitigation.get('description', '')) > 200 else mitigation.get('description', ''),
                    'id': extract_technique_id(mitigation.get('external_references', []))
                })
            
            elif relationship_type == 'uses':
                if source_ref in groups:
                    group = groups[source_ref]
                    result['groups'].append({
                        'name': group.get('name', ''),
                        'description': group.get('description', '')[:200] + '...' if len(group.get('description', '')) > 200 else group.get('description', ''),
                        'id': extract_technique_id(group.get('external_references', []))
                    })
                elif source_ref in software:
                    sw = software[source_ref]
                    result['software'].append({
                        'name': sw.get('name', ''),
                        'description': sw.get('description', '')[:200] + '...' if len(sw.get('description', '')) > 200 else sw.get('description', ''),
                        'id': extract_technique_id(sw.get('external_references', []))
                    })
    
    return result

def process_stix_data(stix_data: Dict) -> Dict:
    """Process STIX data and organize by object types."""
    objects_by_type = defaultdict(dict)
    relationships = []
    
    for obj in stix_data.get('objects', []):
        obj_type = obj.get('type')
        obj_id = obj.get('id')
        
        if obj_type == 'relationship':
            relationships.append(obj)
        elif obj_id:
            objects_by_type[obj_type][obj_id] = obj
    
    return {
        'attack_patterns': objects_by_type.get('attack-pattern', {}),
        'mitigations': objects_by_type.get('course-of-action', {}),
        'groups': objects_by_type.get('intrusion-set', {}),
        'software': objects_by_type.get('malware', {}) | objects_by_type.get('tool', {}),
        'relationships': relationships
    }

def extract_technique_data(attack_pattern: Dict, processed_data: Dict) -> Dict:
    """Extract comprehensive technique data from an attack pattern object."""
    technique_id = extract_technique_id(attack_pattern.get('external_references', []))
    
    if not technique_id:
        return None
    
    # Find relationships for this technique
    relationships_data = find_relationships(
        attack_pattern.get('id', ''),
        processed_data['relationships'],
        processed_data['mitigations'],
        processed_data['groups'],
        processed_data['software']
    )
    
    # Extract procedure examples from description
    description = attack_pattern.get('description', '')
    procedure_examples = []
    
    # Simple extraction of examples mentioned in description
    if 'example' in description.lower() or 'observed' in description.lower():
        # This is a simplified approach - in practice, you might want more sophisticated parsing
        sentences = description.split('.')
        for sentence in sentences:
            if any(keyword in sentence.lower() for keyword in ['example', 'observed', 'used by', 'employed by']):
                procedure_examples.append(sentence.strip() + '.')
    
    technique_data = {
        'technique_id': technique_id,
        'name': attack_pattern.get('name', ''),
        'description': description,
        'tactics': extract_tactics(attack_pattern.get('kill_chain_phases', [])),
        'platforms': attack_pattern.get('x_mitre_platforms', []),
        'detection': attack_pattern.get('x_mitre_detection', ''),
        'mitigations': relationships_data['mitigations'],
        'data_sources': attack_pattern.get('x_mitre_data_sources', []),
        'procedure_examples': procedure_examples,
        'related_groups': relationships_data['groups'],
        'related_software': relationships_data['software'],
        'external_references': extract_external_references(attack_pattern.get('external_references', [])),
        'tags': {
            'is_subtechnique': attack_pattern.get('x_mitre_is_subtechnique', False),
            'deprecated': attack_pattern.get('x_mitre_deprecated', False),
            'domains': attack_pattern.get('x_mitre_domains', [])
        },
        'version': attack_pattern.get('x_mitre_version', ''),
        'created': attack_pattern.get('created', ''),
        'modified': attack_pattern.get('modified', ''),
        'permissions_required': attack_pattern.get('x_mitre_permissions_required', []),
        'impact_type': attack_pattern.get('x_mitre_impact_type', []),
        'system_requirements': attack_pattern.get('x_mitre_system_requirements', []),
        'defense_bypassed': attack_pattern.get('x_mitre_defense_bypassed', []),
        'remote_support': attack_pattern.get('x_mitre_remote_support', False)
    }
    
    return technique_data

def process_folder(folder_path: str, output_filename: str):
    """Process all JSON files in a folder and create consolidated output."""
    print(f"\nProcessing folder: {folder_path}")
    
    if not os.path.exists(folder_path):
        print(f"Warning: Folder {folder_path} does not exist")
        return
    
    json_files = glob.glob(os.path.join(folder_path, "*.json"))
    
    if not json_files:
        print(f"No JSON files found in {folder_path}")
        return
    
    # Sort files to process them in order
    json_files.sort()
    
    output_path = os.path.join(os.path.dirname(folder_path), output_filename)
    all_technique_ids = set()  # Track unique technique IDs
    total_techniques = 0
    processed_files = []
    
    # Initialize output file with metadata
    initial_data = {
        'metadata': {
            'source': f'MITRE ATT&CK {folder_path.split("/")[-1]}',
            'extraction_date': '2025-07-29',
            'total_techniques': 0,  # Will be updated at the end
            'description': f'Comprehensive technique data extracted from {folder_path.split("/")[-1]} MITRE ATT&CK framework',
            'processed_files': []  # Will be updated
        },
        'techniques': []
    }
    
    # Write initial structure
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(initial_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"  ✗ Error creating output file {output_filename}: {e}")
        return
    
    for json_file in json_files:
        filename = os.path.basename(json_file)
        print(f"  Processing: {filename}")
        
        try:
            # Load and process the file
            with open(json_file, 'r', encoding='utf-8') as f:
                stix_data = json.load(f)
            
            # Process and organize the STIX data
            processed_data = process_stix_data(stix_data)
            
            # Extract technique data
            file_techniques = []
            attack_patterns = processed_data['attack_patterns']
            
            print(f"    Processing {len(attack_patterns)} attack patterns...")
            
            for i, attack_pattern in enumerate(attack_patterns.values(), 1):
                if i % 100 == 0:  # Progress indicator
                    print(f"    Progress: {i}/{len(attack_patterns)} ({i/len(attack_patterns)*100:.1f}%)")
                
                technique_data = extract_technique_data(attack_pattern, processed_data)
                if technique_data and technique_data['technique_id'] not in all_technique_ids:
                    file_techniques.append(technique_data)
                    all_technique_ids.add(technique_data['technique_id'])
            
            # Clear memory
            del stix_data
            del processed_data
            
            print(f"    Extracted {len(file_techniques)} new unique techniques")
            
            # Append to output file
            if file_techniques:
                append_techniques_to_file(output_path, file_techniques)
                total_techniques += len(file_techniques)
            
            processed_files.append(filename)
            
        except Exception as e:
            print(f"    Error processing {json_file}: {e}")
            continue
    
    # Update metadata in the final file
    update_metadata(output_path, total_techniques, processed_files)
    
    print(f"  ✓ Successfully created {output_filename} with {total_techniques} unique techniques")

def append_techniques_to_file(output_path: str, new_techniques: List[Dict]):
    """Append new techniques to the existing output file."""
    try:
        # Read existing data
        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Append new techniques
        data['techniques'].extend(new_techniques)
        
        # Sort by technique ID
        data['techniques'].sort(key=lambda x: x['technique_id'])
        
        # Write back to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    except Exception as e:
        print(f"    Warning: Error appending to file: {e}")

def update_metadata(output_path: str, total_techniques: int, processed_files: List[str]):
    """Update the metadata in the final output file."""
    try:
        # Read existing data
        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Update metadata
        data['metadata']['total_techniques'] = total_techniques
        data['metadata']['processed_files'] = processed_files
        
        # Write back to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    except Exception as e:
        print(f"    Warning: Error updating metadata: {e}")

def main():
    """Main function to process all ATT&CK data folders."""
    print("MITRE ATT&CK Data Extraction Script")
    print("=" * 50)
    
    # Define the folders and their output files
    folders_to_process = [
        ('attack-stix-data/enterprise-attack', 'enterprise-attack.json'),
        ('attack-stix-data/ics-attack', 'ics-attack.json'),
        ('attack-stix-data/mobile-attack', 'mobile-attack.json')
    ]
    
    # Get the script directory to ensure proper paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    for folder_name, output_file in folders_to_process:
        folder_path = os.path.join(script_dir, folder_name)
        process_folder(folder_path, output_file)
    
    print("\n" + "=" * 50)
    print("Data extraction completed!")
    print("\nOutput files created:")
    for _, output_file in folders_to_process:
        output_path = os.path.join(script_dir, output_file)
        if os.path.exists(output_path):
            size = os.path.getsize(output_path) / (1024 * 1024)  # Size in MB
            print(f"  • {output_file} ({size:.2f} MB)")

if __name__ == "__main__":
    main()