#!/usr/bin/env python
# -*- coding: utf-8 -*-
################################################################################
##
## Project: NextGIS installer repository synchronizer
## Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
## Copyright (c) 2019 NextGIS <info@nextgis.com>
## License: GPL v.2
##
################################################################################

import argparse
import os
import xml.etree.ElementTree as ET
import requests
from tqdm import tqdm
import tempfile
import hashlib
import json
from shutil import copyfile, rmtree, copytree
import subprocess
import datetime

client_id = '8Mx0qxewubZXLA205sQuaeirHrQ7VdeIxazDjgPo'
auth_url = 'https://my.nextgis.com/oauth2/token/'
api_endpoint = 'https://my.nextgis.com/api/v1'
license_package_name = 'com.nextgis.license'
license_base_version = '1.0'
license_version = 0
update_package_name = 'com.nextgis.nextgis_updater'

def parse_arguments():
    parser = argparse.ArgumentParser(description='Create or update NextGIS desktop software installer repository.')
    parser.add_argument('-i', dest='input_url', required=True, help='NextGIS installer repository URL')
    parser.add_argument('-u', dest='user', required=False, help='NextGIS user login (nextgis id)')
    parser.add_argument('-p', dest='password', required=False, help='NextGIS user password (nextgis id password)')
    parser.add_argument('-pf', dest='password_file', required=False, help='NextGIS user and password (nextgis id password) file. First line is login, second - password')
    parser.add_argument('-o', dest='output', required=True, help='Local NextGIS installer repository path')
    parser.add_argument('-l', dest='license', action='store_true', required=False, help='Generate license package')

    return parser.parse_args()

def local_updates(local_updates_root):
    output = {}
    if local_updates_root is None:
        return output
    for child in local_updates_root:
        if child.tag == 'PackageUpdate':
            name = child.find('Name')
            sha1 = child.find('SHA1')
            if name is None or sha1 is None:
                continue
            output[name.text] = sha1.text

            if name.text == license_package_name:
                version_tag = child.find('Version')
                global license_version
                license_version = int(version_tag.text.replace(license_base_version + '-', ''))

    return output

def load_package(url, local_package_updates, path, local_updates_root, package_update_tag):

    name_tag = package_update_tag.find('Name')
    if name_tag is None:
        print('Name tag not found. Skip package')
        return
    name = name_tag.text

    sha1_tag = package_update_tag.find('SHA1')
    if sha1_tag is None:
        print('SHA1 tag not found. Skip package ' + name)
        return
    sha1 = sha1_tag.text

    if name in local_package_updates and sha1 == local_package_updates[name]:
        print('No update needed. Skip package ' + name)
        local_updates_root.append(package_update_tag)
        return

    version_tag = package_update_tag.find('Version')
    if version_tag is None:
        print('Version tag not found. Skip package ' + name)
        return
    version = version_tag.text

    # Skip updater 
    if name == update_package_name:
        print('Skip package ' + name)
        return

    da_tag = package_update_tag.find('DownloadableArchives')
    da = [version + 'meta.7z']
    if da_tag is not None:
        da_files = da_tag.text.split(',')
        for da_file in da_files:
            da.append(version + da_file)
            da.append(version + da_file + '.sha1')

    package_dir = os.path.join(path, name)
    if not os.path.exists(package_dir):
        os.makedirs(package_dir)
    else:
        for the_file in os.listdir(package_dir):
            file_path = os.path.join(package_dir, the_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)

    print('Download files for package ' + name)

    for da_item in da:
        download_url = url + '/' + name + '/' + da_item
        response = requests.get(download_url, stream=True)

        block_size = 256 * 1024
        total_size = int(response.headers.get('content-length', 0)) / block_size

        with open(os.path.join(package_dir, da_item), "wb") as handle:
            for data in tqdm(response.iter_content(block_size), desc=da_item, total=total_size):
                handle.write(data)

    local_updates_root.append(package_update_tag)

def sha1(path):
    hasher = hashlib.sha1()
    with open(path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()

def create_license_pakage(user, password, local_package_updates, path, local_updates_root, is_win):
    s = requests.Session()
    payload = {'grant_type': 'password', 'client_id': client_id, 'username': user, 'password': password, 'scope': 'user_info.read'}
    req = s.post(auth_url, data=payload)
    dictionary = req.json()
    access_token = dictionary.get('access_token')
    headers = {'Authorization': 'Bearer ' + access_token}

    req = s.get(api_endpoint + '/user_info/', headers=headers)
    user_info = req.json()
    user_name = user_info['username']
    first_name = user_info['first_name']
    last_name = user_info['last_name']
    nextgis_guid = user_info['nextgis_guid']
    email = user_info['email']

    req = s.get(api_endpoint + '/support_info/', headers=headers)
    support_info = req.json()
    supported = support_info['supported']
    sign = support_info['sign']
    start_date = support_info['start_date']
    end_date = support_info['end_date']

    license_package_name = 'com.nextgis.license'
    package_dir = os.path.join(tempfile.gettempdir(), license_package_name)
    license_dir = ''
    if is_win:
        license_dir = os.path.join(package_dir, 'share', 'license')
    else:
        license_dir = os.path.join(package_dir, 'usr', 'share', 'license')
    if not os.path.exists(license_dir):
        os.makedirs(license_dir)

    # Get avatar
    avatar_url = 'https://www.gravatar.com/avatar/{}?s=64&r=pg&d=robohash'.format(hashlib.md5(email.lower()).hexdigest())
    response = s.get(avatar_url, stream=True)
    with open(os.path.join(license_dir, 'avatar'), "wb") as handle:
        for data in tqdm(response.iter_content(), desc='Avatar'):
            handle.write(data)

    # Get key file
    response = s.get(api_endpoint + '/rsa_public_key/', stream=True)
    key_path = os.path.join(license_dir, 'public.key')
    with open(key_path, "wb") as handle:
        for data in tqdm(response.iter_content(), desc='public.key'):
            handle.write(data)

    # Create user and support info
    license_data = {
        'username': user_name,
        'first_name': first_name,
        'last_name': last_name,
        'nextgis_guid': nextgis_guid,
        'email': email,
        'supported': supported,
        'sign': sign,
        'start_date': start_date,
        'end_date': end_date,
    }

    lic_path = os.path.join(license_dir, 'license.json')
    with open(lic_path, 'w') as outfile:
        json.dump(license_data, outfile)

    # Check change of public.key and license.json
    is_same = False
    prev_lic_path = os.path.join(package_dir, 'license.json.prev')
    if os.path.exists(prev_lic_path):
        sha1_current = sha1(lic_path)
        sha1_prev = sha1(prev_lic_path)

        is_same = sha1_prev == sha1_current

    prev_key_path = os.path.join(package_dir, 'public.key.prev')
    if is_same and os.path.exists(prev_key_path):
        sha1_current = sha1(key_path)
        sha1_prev = sha1(prev_key_path)

        is_same = sha1_prev == sha1_current

    copyfile(lic_path, prev_lic_path)
    copyfile(key_path, prev_key_path)

    # Create 7z archive
    share_arch = os.path.join(package_dir, 'share.7z')
    subprocess.call(['7z', 'a', share_arch, os.path.join(package_dir, 'share')])
    # Create SHA1 sign
    sha1Hash = sha1(share_arch)

    with open(os.path.join(package_dir, 'share.7z.sha1'), 'w') as outfile:
        outfile.write(sha1Hash)

    # Create meta
    meta_dir = os.path.join(package_dir, license_package_name)
    if not os.path.exists(meta_dir):
        os.makedirs(meta_dir)

    if not is_same:
        meta_arch = os.path.join(package_dir, 'meta.7z')
        subprocess.call(['7z', 'a', meta_arch, meta_dir])

    sha1Hash = sha1(os.path.join(package_dir, 'meta.7z'))

    # If sha1 change update version
    version = license_base_version + '-' + str(license_version)
    if not is_same:
        version = license_base_version + '-' + str(license_version + 1)
    # Add dummy package
    new_package_dir = os.path.join(path, license_package_name)
    if os.path.exists(new_package_dir):
        rmtree(new_package_dir)
    os.makedirs(new_package_dir)

    # Copy files
    copyfile(os.path.join(package_dir, 'share.7z'), os.path.join(new_package_dir, version + 'share.7z'))
    copyfile(os.path.join(package_dir, 'share.7z.sha1'), os.path.join(new_package_dir, version + 'share.7z.sha1'))
    copyfile(os.path.join(package_dir, 'meta.7z'), os.path.join(new_package_dir, version + 'meta.7z'))

    # Add license package tag
    for child in local_updates_root:
        if child.tag == 'PackageUpdate':
            name = child.find('Name')
            if name is None:
                continue
            if name.text == 'com.nextgis.common.ngstd4' or name.text == 'com.nextgis.common.ngstd5':
                dep = child.find('Dependencies')
                if dep is not None:
                    dep.text = dep.text + ',' + license_package_name

    pa = ET.SubElement(local_updates_root, 'PackageUpdate')
    pa_name = ET.SubElement(pa, 'Name')
    pa_name.text = license_package_name
    pa_dname = ET.SubElement(pa, 'DisplayName')
    pa_dname.text = 'License keys'
    pa_desc = ET.SubElement(pa, 'Description')
    pa_desc.text = 'Enterprise license keys'
    pa_date = ET.SubElement(pa, 'ReleaseDate')
    pa_date.text = datetime.date.today().strftime("%Y-%m-%d")
    pa_version = ET.SubElement(pa, 'Version')
    pa_version.text = version
    pa_uf = ET.SubElement(pa, 'UpdateFile')
    file_size = os.path.getsize(os.path.join(new_package_dir, version + 'share.7z'))
    pa_uf.set('CompressedSize', str(file_size))
    pa_uf.set('UncompressedSize', str(file_size))
    pa_uf.set('OS', 'Any')
    pa_da = ET.SubElement(pa, 'DownloadableArchives')
    pa_da.text = 'share.7z'
    pa_v = ET.SubElement(pa, 'Virtual')
    pa_v.text = 'true'
    pa_sha1 = ET.SubElement(pa, 'SHA1')
    pa_sha1.text =  sha1Hash

def get_user_password(args):
    if args.password_file is not None:
        with open(args.password_file) as f:
            content = f.readlines()
            return content[0].strip(), content[1].strip()
    return args.user, args.password


if __name__ == "__main__":

    args = parse_arguments()

    tmp_dir = args.output + '_tmp'
    if os.path.exists(tmp_dir):
        rmtree(tmp_dir)

    if os.path.exists(args.output):
        copytree(args.output, tmp_dir)

    local_updates_root = None
    local_updates_path = os.path.join(tmp_dir, 'Updates.xml')
    local_package_updates = {}
    if os.path.exists(local_updates_path):
        local_package_updates = local_updates(ET.parse(local_updates_path).getroot())

    # Prepare local Updates.xml
    local_updates_root = ET.Element('Updates')
    app_name = ET.SubElement(local_updates_root, 'ApplicationName')
    app_name.text = '{AnyApplication}'
    app_version = ET.SubElement(local_updates_root, 'ApplicationVersion')
    app_version.text = '1.0.0'
    checksum = ET.SubElement(local_updates_root, 'Checksum')
    checksum.text = 'true'

    # Get remote Updates.xml
    remote_updates_url = args.input_url + '/Updates.xml'
    r = requests.get(remote_updates_url)
    remote_updates_root = ET.fromstring(r.content)

    for child in remote_updates_root:
        if child.tag == 'PackageUpdate':
            load_package(args.input_url, local_package_updates, tmp_dir, local_updates_root, child)

    if args.license:
        user, password = get_user_password(args)
        if user is not None and password is not None:
            is_win = 'repository-win' in args.input_url
            # Get license.key information and create license dummy package
            create_license_pakage(user, password, local_package_updates, tmp_dir, local_updates_root, is_win)

    ET.ElementTree(local_updates_root).write(os.path.join(tmp_dir, 'Updates.xml'))

    # Switch to new repository only on success
    if os.path.exists(args.output):
        rmtree(args.output)
    os.rename(tmp_dir, args.output)

    subprocess.call(['chmod', '-R', '0755', args.output])
