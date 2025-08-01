#!/usr/bin/env python3
"""
Setup script for Ansible FreeBSD Jail Connection Plugin.

This setup script allows for pip installation of the connection plugin.
"""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read version from the plugin file
def get_version():
    """Extract version from plugin docstring."""
    with open('jailexec.py', 'r') as f:
        content = f.read()
        # Look for version in docstring or set a default
        return "1.0.0"  # Update this as needed

setup(
    name='ansible-jailexec',
    version=get_version(),
    author='Christian Hofstede-Kuhn',
    author_email='christian@hofstede.it',
    description='Ansible connection plugin for FreeBSD jails via jexec over SSH',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/chofstede/ansible_jailexec',
    py_modules=['jailexec'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: System :: Systems Administration',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Framework :: Ansible',
    ],
    python_requires='>=3.7',
    install_requires=[
        'ansible>=2.9',
    ],
    extras_require={
        'test': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'pytest-mock>=3.10.0',
            'coverage>=7.0.0',
        ],
        'dev': [
            'flake8>=6.0.0',
            'pylint>=2.15.0',
            'black>=23.0.0',
            'isort>=5.12.0',
            'mypy>=1.0.0',
        ],
    },
    entry_points={
        'ansible.modules': [
            'jailexec = jailexec:Connection',
        ],
    },
    keywords='ansible freebsd jail jexec connection plugin ssh',
    project_urls={
        'Bug Reports': 'https://github.com/chofstede/ansible_jailexec/issues',
        'Source': 'https://github.com/chofstede/ansible_jailexec',
        'Documentation': 'https://github.com/chofstede/ansible_jailexec/wiki',
    },
    include_package_data=True,
    zip_safe=False,
)