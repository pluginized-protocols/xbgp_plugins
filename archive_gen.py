#! /usr/bin/env python3

import sys
import os
from re import search

import tarfile
import json

skipped = [
    'docs',
    'git',
    'venv',
    'cmake',
    'idea',
    'xbgp_compliant_api',
    'prove_stuffs',
    'plugins'
]


def generate_plugin(plugins_dir: str, plugin_base_dir: str, manifest: str, plugin_headers: list):
    """ parse manifest """
    with open(os.path.join(plugin_base_dir, manifest), 'r') as fd:
        manifest_content = json.load(fd)

    """ extract plugin name """
    plugin_name = manifest_content['name']

    """ collect source code to add """
    objs = ['%s.c' % data['obj'][:-2] for _, data in manifest_content['obj_code_list'].items()]

    """ collect prove stuff """
    prove_stuffs = [file for file in os.listdir('prove_stuffs') if file[-2:] in ['.h', '.c']]

    with tarfile.open('%s/%s.tar.bz2' % (plugins_dir, plugin_name), 'w:bz2', dereference=True) as tar:
        """ add source code to archive """
        for obj in objs:
            tar.add(os.path.join(plugin_base_dir, obj), '%s/%s' % (plugin_name, obj))
        for header in plugin_headers:
            tar.add(header, '%s/%s' % (plugin_name, header.split('/')[-1]))
        tar.add(os.path.join(plugin_base_dir, manifest), '%s/manifest.json' % plugin_name)
        tar.add(os.path.join(plugin_base_dir, 'Makefile'), '%s/Makefile' % plugin_name)

        """ add common xbgp files """
        tar.add('xbgp_compliant_api')
        for file in prove_stuffs:
            tar.add(os.path.join('prove_stuffs', file))
        tar.add('byte_manip.h')


def usage():
    print("Usage: %s [plugin_dir]", sys.argv[0])
    exit()


if __name__ == "__main__":
    if len(sys.argv) > 2:
        usage()

    plugin_dir = "plugins" if len(sys.argv) != 2 else sys.argv[1]
    if not os.path.exists(plugin_dir):
        os.mkdir(plugin_dir)

    dirs = list(filter(lambda item: os.path.isdir(item), os.listdir()))
    for plugin_base in filter(lambda y: len(list(filter(lambda x: search(x, y) is not None, skipped))) == 0, dirs):
        content = os.listdir(plugin_base)
        headers = [os.path.join(plugin_base, header) for header in filter(lambda file: file[-2:] == '.h', content)]
        for entry in content:
            if '.plugin' in entry:
                generate_plugin(plugin_dir, plugin_base, entry, headers)
            elif os.path.isdir(new_plugin_base := os.path.join(plugin_base, entry)):
                for entry_subdir in os.listdir(new_plugin_base):
                    if '.plugin' in entry_subdir:
                        generate_plugin(plugin_dir, new_plugin_base, entry_subdir, headers)
