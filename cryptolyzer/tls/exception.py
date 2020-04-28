# -*- coding: utf-8 -*-


class TlsAlert(ValueError):
    def __init__(self, description):
        super(TlsAlert, self).__init__()

        self.description = description

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return 'TlsAlert(TlsAlertDescription.{})'.format(self.description.name)
