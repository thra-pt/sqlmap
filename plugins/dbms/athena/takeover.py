#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "on Athena it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "on Athena it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "on Athena it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "on Athena it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)
