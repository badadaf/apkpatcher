#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import shutil
import requests
import tempfile
import os.path
import argparse
import subprocess


class BColors:
    COLOR_BLUE = '\033[94m'
    COLOR_RED_BG = '\033[101m'
    COLOR_RED = '\033[91m'
    COLOR_GREEN = '\033[92m'
    COLOR_BOLD = '\033[1m'
    COLOR_ENDC = '\033[0m'

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ApkParser:
    apk_file_path = None
    apk_tmp_dir = None

    VERBOSITY_LOW = 1   # only 'error' and 'done' messages
    VERBOSITY_MID = 2   # 'adding' messages too
    VERBOSITY_HIGH = 3  # all messages
    VERBOSITY = VERBOSITY_LOW

    def __init__(self, apk_file_path=None):
        self.apk_file_path = apk_file_path

    def set_verbosity(self, verbosity_level):
        self.VERBOSITY = verbosity_level

    def print_info(self, msg: str):
        if self.VERBOSITY >= self.VERBOSITY_HIGH:
            sys.stdout.write(BColors.COLOR_BLUE + '[*] {0}\n'.format(msg) + BColors.ENDC)

    def print_done(self, msg: str):
        if self.VERBOSITY >= self.VERBOSITY_LOW:
            sys.stdout.write(BColors.COLOR_GREEN + '[+] {0}\n'.format(msg) + BColors.ENDC)

    def print_warn(self, msg: str):
        if self.VERBOSITY >= self.VERBOSITY_LOW:
            sys.stdout.write(BColors.COLOR_RED + '[-] {0}\n'.format(msg) + BColors.ENDC)

    def has_satisfied_dependencies(self, action='all'):
        flag = True
        self.print_info('Checking dependencies...')


        # Check Frida
        try:
            subprocess.check_output(['frida', '--version'])
        except Exception:
            flag = False
            self.print_warn('Frida is not installed')


        # Check aapt
        if action in ['all']:
            try:
                subprocess.check_output(['aapt', 'version'])
            except Exception:
                flag = False
                self.print_warn('aapt is not installed')


        # Check apktool
        if action in ['all']:
            try:
                subprocess.check_output(['apktool', '--version'])
            except Exception:
                self.print_warn('Apktool is not installed')
                flag = False


        # Check unxz
        if action in ['all']:
            try:
                subprocess.check_output(['unxz', '--version'])
            except Exception:
                flag = False
                self.print_warn('unxz is not installed')


        # Check Zipalign
        if action in ['all']:
            cmd_output = subprocess.check_output(['zipalign;echo'], stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        if 'zip alignment' not in cmd_output.lower():
            flag = False
            self.print_warn('zipalign is not installed')

        return flag

    def update_apkpatcher_gadgets(self):
        if not self.has_satisfied_dependencies():
            self.print_warn('One or more dependencies are missing!')
            return False

        self.print_info('Updating frida gadgets')
        frida_version = subprocess.check_output(['frida', '--version']).decode('utf-8').strip()
        self.print_info('Frida version: {0}'.format(frida_version))

        github_link = 'https://api.github.com/repos/frida/frida/releases'

        response = requests.get(github_link).text
        releases = json.loads(response)

        release_link = None

        for release in releases:
            if release['tag_name'] == frida_version:
                release_link = release['url']
                break

        response = requests.get(release_link).text
        release_content = json.loads(response)

        assets = release_content['assets']

        list_gadgets = []
        for asset in assets:
            if 'gadget' in asset['name'] and 'android' in asset['name']:
                gadget = dict()
                gadget['name'] = asset['name']
                gadget['url'] = asset['browser_download_url']

                list_gadgets.append(gadget)

        current_folder = os.path.dirname(os.path.abspath(__file__))
        gadgets_folder = os.path.join(current_folder, 'gadgets')
        target_folder = os.path.join(gadgets_folder, frida_version)

        if not os.path.isdir(target_folder):
            os.makedirs(target_folder)

        downloaded_files = []
        for gadget in list_gadgets:
            gadget_file_path = os.path.join(target_folder, gadget['name'])

            if os.path.isfile(gadget_file_path.replace('.xz', '')):
                self.print_info('{0} already exists. Skipping.'.format(gadget['name']))
            else:
                self.download_file(gadget['url'], gadget_file_path)
                downloaded_files.append(gadget_file_path)

        self.print_info('Extracting downloaded files...')

        for downloaded_file in downloaded_files:
            subprocess.check_output(['unxz', downloaded_file])

        self.print_done('Done! Gadgets were updated')

        return True

    def download_file(self, url, target_path):
        file_name = target_path.split('/')[-1]
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')
        total_length = int(total_length)

        with open(target_path, 'wb') as f:
            downloaded = 0

            if self.VERBOSITY >= self.VERBOSITY_HIGH:
                sys.stdout.write('\r{0}[+] Downloading {1} - 000 %%{2}'
                                 .format(BColors.COLOR_BLUE, file_name, BColors.COLOR_ENDC))

                sys.stdout.flush()

            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    downloaded += len(chunk)
                    percentage = int(downloaded * 100 / total_length)

                    if self.VERBOSITY >= self.VERBOSITY_HIGH:
                        sys.stdout.write('\r{0}[+] Downloading {1} - {2:03d} %%{3}'
                                         .format(BColors.COLOR_BLUE, file_name, percentage, BColors.COLOR_ENDC))

                        sys.stdout.flush()

                    f.write(chunk)

        if self.VERBOSITY >= self.VERBOSITY_HIGH:
            sys.stdout.write('\n')

    def get_recommended_gadget(self):
        ret = None

        self.print_info('Trying to identify the right frida-gadget...')
        self.print_info('Waiting for device...')
        os.system('adb wait-for-device')
        abi = subprocess.check_output(['adb', 'shell', 'getprop ro.product.cpu.abi']).decode('utf-8').strip()

        self.print_info('The abi is {0}'.format(abi))

        frida_version = subprocess.check_output(['frida', '--version']).strip().decode('utf-8')
        current_folder = os.path.dirname(os.path.abspath(__file__))
        gadgets_folder = os.path.join(current_folder, 'gadgets')
        target_folder = os.path.join(gadgets_folder, frida_version)

        if os.path.isdir(target_folder):
            dir_list = os.listdir(target_folder)
            gadget_files = [f for f in dir_list if os.path.isfile(os.path.join(target_folder, f))]
        else:
            self.print_warn('Gadget folder not found. Try "python {0} --update"'.format(sys.argv[0]))
            return ret

        if abi in ['armeabi', 'armeabi-v7a']:
            for gadget_file in gadget_files:
                if 'arm' in gadget_file and '64' not in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        elif abi is 'arm64-v8a' or 'arm64' in abi:
            for gadget_file in gadget_files:
                if 'arm64' in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        elif abi is 'x86':
            for gadget_file in gadget_files:
                if 'i386' in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        elif abi is 'x86_64':
            for gadget_file in gadget_files:
                if 'x86_64' in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        if ret is None:
            self.print_warn('No recommended gadget file was found.')
        else:
            self.print_info('Architecture identified ({0}). Gadget was selected.' .format(abi))

        return ret

    def extract_apk(self, apk_path, destination_path, extract_resources=True):
        if extract_resources:
            self.print_info('Extracting {0} (with resources) to {1}'.format(apk_path, destination_path))
            self.print_info('Some errors may occur while decoding resources that have framework dependencies')

            subprocess.check_output(['apktool', 'd', '-o', destination_path, apk_path, '-f'])
        else:
            self.print_info('Extracting {0} (without resources) to {1}'.format(apk_path, destination_path))
            subprocess.check_output(['apktool', '-r', 'd', '-o', destination_path, apk_path, '-f'])

    def has_permission(self, permission_name, apk_path):
        permissions = subprocess.check_output(['aapt', 'dump', 'permissions', apk_path]).decode('utf-8')

        if permission_name in permissions:
            self.print_info('The app {0} has the permission "{1}"'.format(apk_path, permission_name))
            return True
        else:
            self.print_info('The app {0} doesn\'t have the permission "{1}"'.format(apk_path, permission_name))
            return False

    def get_entrypoint_class_name(self, apk_path):
        dump_lines = subprocess.check_output(['aapt', 'dump', 'badging', apk_path]).decode('utf-8').split('\n')
        entrypoint_class = None

        for line in dump_lines:
            if 'launchable-activity:' in line:
                name_start = line.find('name=')
                entrypoint_class = line[name_start:].split(' ')[0].replace('name=', '').replace('\'', '').replace('"', '')
                break

        if entrypoint_class is None:
            self.print_warn('Something was wrong while getting launchable-activity')

        return entrypoint_class

    def get_entrypoint_smali_path(self, base_path, entrypoint_class):
        files_at_path = os.listdir(base_path)
        entrypoint_final_path = None

        for file in files_at_path:
            if file.startswith('smali'):
                entrypoint_tmp = os.path.join(base_path, file, entrypoint_class.replace('.', '/') + '.smali')

                if os.path.isfile(entrypoint_tmp):
                    entrypoint_final_path = entrypoint_tmp
                    break

        if entrypoint_final_path is None:
            self.print_warn('Couldn\'t find the application entrypoint')
        else:
            self.print_info('Found application entrypoint at {0}'.format(entrypoint_final_path))

        return entrypoint_final_path

    def create_temp_folder_for_apk(self, apk_path):
        system_tmp_dir = tempfile.gettempdir()
        apkpatcher_tmp_dir = os.path.join(system_tmp_dir, 'apkpatcher_tmp')

        apk_name = apk_path.split('/')[-1]

        final_tmp_dir = os.path.join(apkpatcher_tmp_dir, apk_name.replace('.apk', '').replace('.', '_'))

        if os.path.isdir(final_tmp_dir):
            self.print_info('App temp dir already exists. Removing it...')
            shutil.rmtree(final_tmp_dir)

        os.makedirs(final_tmp_dir)

        return final_tmp_dir


if __name__ == '__main__':
    try:
        #main()
        print('Porting to Python 3. Not ready yet!!!')
        parser = ApkParser()
        parser.set_verbosity(3)

        badada_patos = '/tmp/apkpatcher/BadadaPatos.apk'
        tmp_path = parser.create_temp_folder_for_apk(badada_patos)

        print(tmp_path)

        parser.extract_apk(badada_patos, tmp_path, False)
        entry_class = parser.get_entrypoint_class_name(badada_patos)
        entry_smali = parser.get_entrypoint_smali_path(tmp_path, entry_class)
        print(entry_smali)

    except KeyboardInterrupt:
        exit(1)
