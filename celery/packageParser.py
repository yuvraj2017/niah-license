import time
import datetime
from time import sleep
import os
import sys
import re
from packagesAdvisory.npmParser import npm_parser
from packagesAdvisory.composerParser import composer_parser
from packagesAdvisory.pypiParser import pypi_parser
from packagesAdvisory.debianParser import debianParser
from packagesAdvisory.ubuntuParser import ubuntuParser
from packagesAdvisory.elixir_hex_advisory import elixir_hex_advisory
from packagesAdvisory.pub_dev_advisory import pub_dev_advisory
from packagesAdvisory.crates_io import crate_scan
from packagesAdvisory.ruby_packages import ruby_info
from time import gmtime, strftime
import configparser
import logging
import os
import sys
import json
from pathlib import Path


class monitor():
    def __init__(self):
        pass


    def run(self):
        # res = npm_parser()
        # res.startParsing('no')
        # print("NPM Package Advisory [ OK ]")

        # res = pypi_parser()
        # res.startParsing('no')
        # print("Pypi Package Advisory [ OK ]")

        # res = composer_parser()
        # res.startParsing('no')
        # print("Composer Package Advisory [ OK ]")

        # res = debianParser()
        # res.intialize()
        # print("Debian Package Advisory [ OK ]")

        # res = ubuntuParser()
        # res.intialize()
        # print("Ubuntu Package Advisory [ OK ]")
    
        # res = elixir_hex_advisory()
        # res.rssfeed()
        # print("Hex Package Advisory [ OK ]")
    
        res = pub_dev_advisory()
        res.rssfeed()
        print("Pub.Dev Package Advisory [ OK ]")

        # res = crate_scan()
        # res.rssfeed()
        # print("Crate Package Advisory [ OK ]")

        # res = ruby_info()
        # res.rssfeed()
        # print("Rubygems Package Advisory [ OK ]")


if __name__ == "__main__":
    res = monitor()
    res.run()


