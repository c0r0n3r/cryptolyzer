# -*- coding: utf-8 -*-

import enum
import six

import attr


@attr.s
class ECParamNumbers(object):
    a = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'a'},
    )
    b = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'b'},
    )
    x = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'x'},
    )
    y = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'y'},
    )


@attr.s
class ECParamWellKnown(object):
    parameter_numbers = attr.ib(validator=attr.validators.instance_of(ECParamNumbers))
    source = attr.ib(validator=attr.validators.instance_of(six.string_types))


class WellKnownECParams(enum.Enum):
    @classmethod
    def from_named_group(cls, named_group):
        return getattr(cls, named_group.name)

    BRAINPOOLP256R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '7D5A0975 FC2C3057 EEF67530 417AFFE7 FB8055C1 26DC5C6C' +
                'E94A4B44 F330B5D9'
            ).replace(' ', ''), 16),
            b=int((
                '26DC5C6C E94A4B44 F330B5D9 BBD77CBF 95841629 5CF7E1CE' +
                '6BCCDC18 FF8C07B6'
            ).replace(' ', ''), 16),
            x=int((
                '8BD2AEB9 CB7E57CB 2C4B482F FC81B7AF B9DE27E1 E3BD23C2' +
                '3A4453BD 9ACE3262'
            ).replace(' ', ''), 16),
            y=int((
                '547EF835 C3DAC4FD 97F8461A 14611DC9 C2774513 2DED8E54' +
                '5C1D54C7 2F046997'
            ).replace(' ', ''), 16),
        ),
        source='RFC5639',
    )
    BRAINPOOLP384R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '7BC382C6 3D8C150C 3C72080A CE05AFA0 C2BEA28E 4FB22787' +
                '139165EF BA91F90F 8AA5814A 503AD4EB 04A8C7DD 22CE2826'
            ).replace(' ', ''), 16),
            b=int((
                '04A8C7DD 22CE2826 8B39B554 16F0447C 2FB77DE1 07DCD2A6' +
                '2E880EA5 3EEB62D5 7CB43902 95DBC994 3AB78696 FA504C11'
            ).replace(' ', ''), 16),
            x=int((
                '1D1C64F0 68CF45FF A2A63A81 B7C13F6B 8847A3E7 7EF14FE3' +
                'DB7FCAFE 0CBD10E8 E826E034 36D646AA EF87B2E2 47D4AF1E'
            ).replace(' ', ''), 16),
            y=int((
                '8ABE1D75 20F9C2A4 5CB1EB8E 95CFD552 62B70B29 FEEC5864' +
                'E19C054F F9912928 0E464621 77918111 42820341 263C5315'
            ).replace(' ', ''), 16),
        ),
        source='RFC5639',
    )
    BRAINPOOLP512R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '7830A331 8B603B89 E2327145 AC234CC5 94CBDD8D 3DF91610' +
                'A83441CA EA9863BC 2DED5D5A A8253AA1 0A2EF1C9 8B9AC8B5' +
                '7F1117A7 2BF2C7B9 E7C1AC4D 77FC94C'
            ).replace(' ', ''), 16),
            b=int((
                '3DF91610 A83441CA EA9863BC 2DED5D5A A8253AA1 0A2EF1C9' +
                '8B9AC8B5 7F1117A7 2BF2C7B9 E7C1AC4D 77FC94CA DC083E67' +
                '984050B7 5EBAE5DD 2809BD63 8016F72'
            ).replace(' ', ''), 16),
            x=int((
                '81AEE4BD D82ED964 5A21322E 9C4C6A93 85ED9F70 B5D916C1' +
                'B43B62EE F4D0098E FF3B1F78 E2D0D48D 50D1687B 93B97D5F' +
                '7C6D5047 406A5E68 8B352209 BCB9F82'
            ).replace(' ', ''), 16),
            y=int((
                '7DDE385D 566332EC C0EABFA9 CF7822FD F209F700 24A57B1A' +
                'A000C55B 881F8111 B2DCDE49 4A5F485E 5BCA4BD8 8A2763AE' +
                'D1CA2B2F A8F05406 78CD1E0F 3AD8089'
            ).replace(' ', ''), 16),
        ),
        source='RFC5639',
    )
    PRIME192V1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFC '
            ).replace(' ', ''), 16),
            b=int((
                '64210519 E59C80E7 0FA7E9AB 72243049 FEB8DEEC C146B9B1 '
            ).replace(' ', ''), 16),
            x=int((
                '188DA80E B03090F6 7CBF20EB 43A18800 F4FF0AFD 82FF1012 '
            ).replace(' ', ''), 16),
            y=int((
                '07192B95 FFC8DA78 631011ED 6B24CDD5 73F977A1 1E794811 '
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    PRIME256V1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                'FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF' +
                'FFFFFFFF FFFFFFFC'
            ).replace(' ', ''), 16),
            b=int((
                '5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6' +
                '3BCE3C3E 27D2604B'
            ).replace(' ', ''), 16),
            x=int((
                '6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0' +
                'F4A13945 D898C296 '
            ).replace(' ', ''), 16),
            y=int((
                '4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE' +
                'CBB64068 37BF51F5 '
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECP224R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFF' +
                'FFFFFFFE'
            ).replace(' ', ''), 16),
            b=int((
                'B4050A85 0C04B3AB F5413256 5044B0B7 D7BFD8BA 270B3943' +
                '2355FFB4'
            ).replace(' ', ''), 16),
            x=int((
                'B70E0CBD 6BB4BF7F 321390B9 4A03C1D3 56C21122 343280D6' +
                '115C1D21'
            ).replace(' ', ''), 16),
            y=int((
                'BD376388 B5F723FB 4C22DFE6 CD4375A0 5A074764 44D58199' +
                '85007E34'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECP384R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
                'FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC '
            ).replace(' ', ''), 16),
            b=int((
                'B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112' +
                '0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF '
            ).replace(' ', ''), 16),
            x=int((
                'AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98' +
                '59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7 '
            ).replace(' ', ''), 16),
            y=int((
                '3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C' +
                'E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F '
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECP521R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
                'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
                'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFC'
            ).replace(' ', ''), 16),
            b=int((
                '0051953E B9618E1C 9A1F929A 21A0B685 40EEA2DA 725B99B3' +
                '15F3B8B4 89918EF1 09E15619 3951EC7E 937B1652 C0BD3BB1' +
                'BF073573 DF883D2C 34F1EF45 1FD46B50 3F00'
            ).replace(' ', ''), 16),
            x=int((
                '00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053F' +
                'B521F828 AF606B4D 3DBAA14B 5E77EFE7 5928FE1D C127A2FF' +
                'A8DE3348 B3C1856A 429BF97E 7E31C2E5 BD66'
            ).replace(' ', ''), 16),
            y=int((
                '01183929 6A789A3B C0045C8A 5FB42C7D 1BD998F5 4449579B' +
                '446817AF BD17273E 662C97EE 72995EF4 2640C550 B9013FAD' +
                '0761353C 7086A272 C24088BE 94769FD1 6650'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECT163K1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                 '00000000 00000000 00000000 00000000 00000000 01'
            ).replace(' ', ''), 16),
            b=int((
                 '00000000 00000000 00000000 00000000 00000000 01'
            ).replace(' ', ''), 16),
            x=int((
                '02FE13C0 537BBC11 ACAA07D7 93DE4E6D 5E5C94EE E8'
            ).replace(' ', ''), 16),
            y=int((
                '0289070F B05D38FF 58321F2E 800536D5 38CCDAA3 D9'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECT233K1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 0000'
            ).replace(' ', ''), 16),
            b=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 0001'
            ).replace(' ', ''), 16),
            x=int((
                '017232BA 853A7E73 1AF129F2 2FF41495 63A419C2 6BF50A4C' +
                '9D6EEFAD 6126'
            ).replace(' ', ''), 16),
            y=int((
                '01DB537D ECE819B7 F70F555A 67C427A8 CD9BF18A EB9B56E0' +
                'C11056FA E6A3'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECT233R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 0001'
            ).replace(' ', ''), 16),
            b=int((
                '0066647E DE6C332C 7F8C0923 BB58213B 333B20E9 CE4281FE' +
                '115F7D8F 90AD'
            ).replace(' ', ''), 16),
            x=int((
                '00FAC9DF CBAC8313 BB2139F1 BB755FEF 65BC391F 8B36F8F8' +
                'EB7371FD 558B'
            ).replace(' ', ''), 16),
            y=int((
                '01006A08 A4190335 0678E585 28BEBF8A 0BEFF867 A7CA3671' +
                '6F7E01F8 1052'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECT283K1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 00000000 0000000'
            ).replace(' ', ''), 16),
            b=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 00000000 0000001'
            ).replace(' ', ''), 16),
            x=int((
                '503213F7 8CA44883 F1A3B816 2F188E55 3CD265F2 3C1567A1' +
                '6876913B 0C2AC245 8492836'
            ).replace(' ', ''), 16),
            y=int((
                '1CCDA380 F1C9E318 D90F95D0 7E5426FE 87E45C0E 8184698E' +
                '45962364 E3411617 7DD2259'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECT409K1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '0000000'
            ).replace(' ', ''), 16),
            b=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '0000001'
            ).replace(' ', ''), 16),
            x=int((
                '060F05F6 58F49C1A D3AB1890 F7184210 EFD0987E 307C84C2' +
                '7ACCFB8F 9F67CC2C 460189EB 5AAAA62E E222EB1B 35540CFE' +
                '9023746'
            ).replace(' ', ''), 16),
            y=int((
                '1E369050 B7C4E42A CBA1DACB F04299C3 460782F9 18EA427E' +
                '6325165E 9EA10E3D A5F6C42E 9C55215A A9CA27A5 863EC48D' +
                '8E0286B'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
    SECT409R1 = ECParamWellKnown(  # pylint: disable=invalid-name
        ECParamNumbers(
            a=int((
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '00000000 00000000 00000000 00000000 00000000 00000000' +
                '0000001'
            ).replace(' ', ''), 16),
            b=int((
                '021A5C2C 8EE9FEB5 C4B9A753 B7B476B7 FD6422EF 1F3DD674' +
                '761FA99D 6AC27C8A 9A197B27 2822F6CD 57A55AA4 F50AE317' +
                'B13545F'
            ).replace(' ', ''), 16),
            x=int((
                '15D4860D 088DDB34 96B0C606 47562604 41CDE4AF 1771D4DB' +
                '01FFE5B3 4E59703D C255A868 A1180515 603AEAB6 0794E54B' +
                'B7996A7'
            ).replace(' ', ''), 16),
            y=int((
                '061B1CFA B6BE5F32 BBFA7832 4ED106A7 636B9C5A 7BD198D0' +
                '158AA4F5 488D08F3 8514F1FD F4B4F40D 2181B368 1C364BA0' +
                '273C706'
            ).replace(' ', ''), 16),
        ),
        source='SEC2',
    )
