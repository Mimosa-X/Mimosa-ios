import json
import os
import sys
import shutil
import tempfile
import plistlib
import argparse
import subprocess
import base64

from BuildEnvironment import run_executable_with_output, check_run_system


# Mirrors BuildConfiguration.profile_name_mapping (output filename -> App ID suffix).
PROFILE_SUFFIX_BY_OUTPUT_NAME = {
    'Telegram': '',
    'Share': '.Share',
    'Widget': '.Widget',
    'NotificationService': '.NotificationService',
    'NotificationContent': '.NotificationContent',
    'Intents': '.SiriIntents',
    'WatchApp': '.watchkitapp',
    'WatchExtension': '.watchkitapp.watchkitextension',
    'BroadcastUpload': '.BroadcastUpload',
}


def load_build_configuration(configuration_path):
    if not os.path.exists(configuration_path):
        print('Could not load build configuration from non-existing path {}'.format(configuration_path))
        sys.exit(1)

    with open(configuration_path) as file:
        configuration_dict = json.load(file)

    for key in ['bundle_id', 'team_id']:
        if key not in configuration_dict:
            print('Configuration at {} does not contain {}'.format(configuration_path, key))
            sys.exit(1)

    return configuration_dict


def application_identifier_for_profile(team_id, bundle_id, profile_output_name):
    suffix = PROFILE_SUFFIX_BY_OUTPUT_NAME.get(profile_output_name)
    if suffix is None:
        return None
    return '{}{}{}'.format(team_id, bundle_id, suffix) if suffix else '{}.{}'.format(team_id, bundle_id)


def patch_bundle_id_in_profile_plist(plist_path, team_id, bundle_id, profile_output_name):
    suffix = PROFILE_SUFFIX_BY_OUTPUT_NAME.get(profile_output_name)
    if suffix is None:
        print('Warning: unknown profile {}, skipping bundle id patch'.format(profile_output_name))
        return

    with open(plist_path, 'rb') as file:
        plist = plistlib.load(file)

    entitlements = plist.get('Entitlements')
    if not isinstance(entitlements, dict):
        print('Warning: profile {} has no Entitlements dict, skipping bundle id patch'.format(profile_output_name))
        return

    old_app_id = entitlements.get('application-identifier')
    if not isinstance(old_app_id, str) or not old_app_id.startswith(team_id + '.'):
        print('Warning: unexpected application-identifier in {}: {}'.format(profile_output_name, old_app_id))
        return

    old_remainder = old_app_id[len(team_id) + 1:]
    if suffix:
        if not old_remainder.endswith(suffix):
            print('Warning: application-identifier suffix mismatch in {}: {}'.format(profile_output_name, old_app_id))
            return
        old_bundle_id = old_remainder[:-len(suffix)]
    else:
        old_bundle_id = old_remainder

    new_app_id = application_identifier_for_profile(team_id, bundle_id, profile_output_name)
    entitlements['application-identifier'] = new_app_id

    def replace_bundle_id(value):
        if isinstance(value, str):
            return value.replace(old_bundle_id, bundle_id)
        if isinstance(value, list):
            return [replace_bundle_id(item) for item in value]
        if isinstance(value, dict):
            return {key: replace_bundle_id(item) for key, item in value.items()}
        return value

    plist['Entitlements'] = replace_bundle_id(entitlements)

    with open(plist_path, 'wb') as file:
        plistlib.dump(plist, file, fmt=plistlib.FMT_XML)

    print('Patched {} application-identifier: {} -> {}'.format(profile_output_name, old_app_id, new_app_id))


def setup_temp_keychain(p12_path, p12_password=''):
    """Create a temporary keychain and import the p12 certificate."""
    keychain_name = 'generate-profiles-temp.keychain'
    keychain_password = 'temp123'

    # Delete if exists
    run_executable_with_output('security', arguments=['delete-keychain', keychain_name], check_result=False)

    # Create keychain
    run_executable_with_output('security', arguments=[
        'create-keychain', '-p', keychain_password, keychain_name
    ], check_result=True)

    # Add to search list
    existing = run_executable_with_output('security', arguments=['list-keychains', '-d', 'user'])
    run_executable_with_output('security', arguments=[
        'list-keychains', '-d', 'user', '-s', keychain_name, existing.replace('"', '')
    ], check_result=True)

    # Unlock and set settings
    run_executable_with_output('security', arguments=['set-keychain-settings', keychain_name])
    run_executable_with_output('security', arguments=[
        'unlock-keychain', '-p', keychain_password, keychain_name
    ])

    # Import p12
    run_executable_with_output('security', arguments=[
        'import', p12_path, '-k', keychain_name, '-P', p12_password,
        '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'
    ], check_result=True)

    # Set partition list for access
    run_executable_with_output('security', arguments=[
        'set-key-partition-list', '-S', 'apple-tool:,apple:', '-k', keychain_password, keychain_name
    ], check_result=True)

    return keychain_name


def cleanup_temp_keychain(keychain_name):
    """Remove the temporary keychain."""
    run_executable_with_output('security', arguments=['delete-keychain', keychain_name], check_result=False)


def get_signing_identity_from_p12(p12_path, p12_password=''):
    """Extract the common name (signing identity) from the p12 certificate."""
    proc = subprocess.Popen(
        ['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:' + p12_password, '-nokeys', '-legacy'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    cert_pem, _ = proc.communicate()

    proc2 = subprocess.Popen(
        ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'oneline,-esc_msb'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    subject, _ = proc2.communicate(cert_pem)
    subject = subject.decode('utf-8').strip()

    # Parse CN from subject line like: subject= C = AE, O = ..., CN = Some Name
    if 'CN = ' in subject:
        cn = subject.split('CN = ')[-1].split(',')[0].strip()
        return cn

    return None


def get_certificate_base64_from_p12(p12_path, p12_password=''):
    """Extract the certificate as base64 from p12 file."""
    # Extract certificate in PEM format
    proc = subprocess.Popen(
        ['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:' + p12_password, '-nokeys', '-legacy'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    cert_pem, _ = proc.communicate()

    # Convert to DER format
    proc2 = subprocess.Popen(
        ['openssl', 'x509', '-outform', 'DER'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    cert_der, _ = proc2.communicate(cert_pem)

    return base64.b64encode(cert_der).decode('utf-8')


def process_provisioning_profile(
    source,
    destination,
    certificate_data,
    signing_identity,
    keychain_name,
    team_id=None,
    bundle_id=None,
    profile_output_name=None,
):
    parsed_plist = run_executable_with_output('security', arguments=['cms', '-D', '-i', source], check_result=True)
    parsed_plist_file = tempfile.mktemp()
    with open(parsed_plist_file, 'w+') as file:
        file.write(parsed_plist)

    if team_id is not None and bundle_id is not None and profile_output_name is not None:
        patch_bundle_id_in_profile_plist(
            plist_path=parsed_plist_file,
            team_id=team_id,
            bundle_id=bundle_id,
            profile_output_name=profile_output_name,
        )

    # Remove all existing developer certificates
    while True:
        result = run_executable_with_output('plutil', arguments=['-remove', 'DeveloperCertificates.0', parsed_plist_file], check_result=False)
        if result is None or 'Could not' in str(result) or result == '':
            # Check if the removal actually failed by trying to extract
            check = run_executable_with_output('plutil', arguments=['-extract', 'DeveloperCertificates.0', 'raw', parsed_plist_file], check_result=False)
            if check is None or 'Could not' in str(check):
                break

    # Insert the new certificate
    run_executable_with_output('plutil', arguments=['-insert', 'DeveloperCertificates.0', '-data', certificate_data, parsed_plist_file])

    # Remove the DER-Encoded-Profile (signature)
    run_executable_with_output('plutil', arguments=['-remove', 'DER-Encoded-Profile', parsed_plist_file])

    # Sign with the certificate from the temporary keychain
    run_executable_with_output('security', arguments=[
        'cms', '-S', '-k', keychain_name, '-N', signing_identity, '-i', parsed_plist_file, '-o', destination
    ], check_result=True)

    os.unlink(parsed_plist_file)


def generate_provisioning_profiles(
    source_path,
    destination_path,
    certs_path,
    team_id=None,
    bundle_id=None,
    configuration_path=None,
    p12_password='',
):
    if configuration_path is not None:
        configuration_dict = load_build_configuration(configuration_path)
        team_id = configuration_dict['team_id']
        bundle_id = configuration_dict['bundle_id']

    p12_path = os.path.join(certs_path, 'SelfSigned.p12')

    if not os.path.exists(p12_path):
        print('{} does not exist'.format(p12_path))
        sys.exit(1)

    if not os.path.exists(destination_path):
        print('{} does not exist'.format(destination_path))
        sys.exit(1)

    certificate_data = get_certificate_base64_from_p12(p12_path, p12_password)
    signing_identity = get_signing_identity_from_p12(p12_path, p12_password)

    if not signing_identity:
        print('Could not extract signing identity from {}'.format(p12_path))
        sys.exit(1)

    print('Using signing identity: {}'.format(signing_identity))
    if team_id is not None and bundle_id is not None:
        print('Patching provisioning profiles for {}.{}'.format(team_id, bundle_id))

    keychain_name = setup_temp_keychain(p12_path, p12_password)

    try:
        for file_name in os.listdir(source_path):
            if file_name.endswith('.mobileprovision'):
                print('Processing {}'.format(file_name))
                profile_output_name = file_name[:-len('.mobileprovision')]
                process_provisioning_profile(
                    source=os.path.join(source_path, file_name),
                    destination=os.path.join(destination_path, file_name),
                    certificate_data=certificate_data,
                    signing_identity=signing_identity,
                    keychain_name=keychain_name,
                    team_id=team_id,
                    bundle_id=bundle_id,
                    profile_output_name=profile_output_name,
                )
        print('Done. Generated {} profiles.'.format(
            len([f for f in os.listdir(destination_path) if f.endswith('.mobileprovision')])
        ))
    finally:
        cleanup_temp_keychain(keychain_name)


def main():
    parser = argparse.ArgumentParser(description='Regenerate fake provisioning profiles.')
    parser.add_argument('--sourcePath', required=True, help='Directory with template .mobileprovision files.')
    parser.add_argument('--destinationPath', required=True, help='Directory to write regenerated profiles.')
    parser.add_argument('--certsPath', required=True, help='Directory containing SelfSigned.p12.')
    parser.add_argument('--configurationPath', help='Optional build configuration JSON with bundle_id and team_id.')
    parser.add_argument('--teamId', help='Override team id used in application-identifier.')
    parser.add_argument('--bundleId', help='Override bundle id used in application-identifier.')
    parser.add_argument('--p12Password', default='', help='Password for SelfSigned.p12.')
    arguments = parser.parse_args()

    team_id = arguments.teamId
    bundle_id = arguments.bundleId
    if arguments.configurationPath is not None:
        configuration_dict = load_build_configuration(arguments.configurationPath)
        team_id = team_id or configuration_dict['team_id']
        bundle_id = bundle_id or configuration_dict['bundle_id']

    generate_provisioning_profiles(
        source_path=arguments.sourcePath,
        destination_path=arguments.destinationPath,
        certs_path=arguments.certsPath,
        team_id=team_id,
        bundle_id=bundle_id,
        p12_password=arguments.p12Password,
    )


if __name__ == '__main__':
    main()
