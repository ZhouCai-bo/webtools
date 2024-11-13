import re
import json
import zlib
import logging
import flask
from io import StringIO
from functools import wraps
from six.moves.urllib_parse import quote
from flask import request, Response, make_response
from webargs.flaskparser import FlaskParser
from werkzeug.routing import BaseConverter

from src import config
from src.base import const


class Json(Response):
    """
    非平铺，新项目采用，格式如
    {
        code: int,
        message: str,
        data: {},
        detail: {}
    }
    error 是API_ERROR里面的常量值
    message 可自己提供message代替默认的
    data 是成功的内容
    detail 是失败的原因，一般不限于使用
    """

    def __init__(self, error=const.API_ERROR.OK, data=None, message=None, detail=None, lang=None):
        lang = lang or request.headers.get('Accept-Language') or CONFIG.API.DEFAULT_LANG
        body = {'code': error[1], 'message': error[2].get(lang, error[2][CONFIG.API.DEFAULT_LANG])}
        if message:
            body['message'] = message
        if data is not None:
            body['data'] = data
        if detail is not None:
            body['detail'] = detail
        super(Json, self).__init__(util.safe_json_dumps(body, ensure_ascii=False),
            status=error[0], content_type='application/json')


class JsonResponse(Json):
    def __init__(self, code=const.API_ERROR.OK, data=None, message=None, locale=None):
        locale = locale or get_locale(request.headers.get('Locale')) or config.DEFAULT_LANG
        super().__init__(error=code, data=data, message=message, lang=locale)


class AccAuthResponse(Json):
    def __init__(self, code=const.API_ERROR.OK, data=None):
        super().__init__(error=code, data=data, lang=config.DEFAULT_LANG)
        self.status = '200'  # 加速服认证接口状态码返回200，非200情况下加速服放过校验


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]


def _get_header(name):
    return request.headers.get(getattr(const.HEADER, name))

'''
def header():
    """
    检查 header
    REQUIRED 中的字段涉及到业务逻辑，是头部必须包含的字段
    OPTIONAL 中的字段仅作为后续变量使用，非必须包含的字段
    """
    WIN_REQUIRED = ['SYSTEM_TYPE', 'LOCALE', 'DEVICE_ID', 'APP_VERSION', 'APP_VERSION_CODE']
    REQUIRED = WIN_REQUIRED + ['BUNDLE_ID']
    IOS_REQUIRED = REQUIRED
    ANDROID_REQUIRED = REQUIRED
    WIN_OPTIONAL = [
        'SEED',
        'SIGN',
        'SESSION_ID',
        'SYSTEM_VERSION',
        'RESOLUTION',
        'NETWORK_TYPE',
        'TIMEZONEOFFSET',
        'DISTINCT_ID',
        'SAFESHELL_UUID',
        'SAFESHELL_UID',
        'VIP_STATE',
        'SUBSCRIPTION_STATE',
    ]
    OPTIONAL = WIN_OPTIONAL + [
        'OPERATOR',
        'PRODUCT',
        'NTES_TRACE_ID',
        'SIGN_STATE',
    ]
    IOS_OPTIONAL = OPTIONAL + [
        'JAIL_BROKEN',
        'DEVICE_IDFA',
        'BUILD_TYPE',
        'RADIO_ACCESS_TECHNOLOGY',
        'CELLULAR_IP',
        'APPLE_SILICON',
    ]
    ANDROID_OPTIONAL = OPTIONAL + [
        'BRAND',
        'MANUFACTURER',
        'MODEL',
        'ROOT',
        'ABI',
        'SCREEN_DPI',
        'SCREEN_SIZE',
        'SYSTEM_DEBUG',
        'ROM',
    ]

    def validate(key):
        """
        返回 (validated, value)
        validated   若通过验证，验证后的值
                    否则返回 False
        value       key 对应的 value 初始值
        """

        def validate_system_type(value):
            ret = convert_system(value)
            return ret if ret else False

        def validate_app_version(value):
            """
            判断 AppVersion 字段是否合乎格式 x.x.x，只校验 iOS
            """
            system = (request.headers.get(const.HEADER.SYSTEM_TYPE) or '').lower()
            if is_android(system):
                matched = re.match(r'^\d+\.\d+\.\d+\.\d+(\.\w+)?$', value or '')
            else:
                matched = re.match(r'^\d+\.\d+\.\d+$', value or '')
            return value if matched else False

        def validate_app_version_code(value):
            """
            判断 AppVersionCode 字段是否合乎格式，只校验安卓
            """
            matched = re.match(r'^\d+$', value or '')
            return int(value) if matched else False

        def validate_locale(value):
            """
            解析用户所使用的语言
            """
            if not value:
                return config.DEFAULT_LANG
            elif value in const.LANG.VALUES:
                return const.LANG.VALUES[value]
            else:
                lang = value.split('_', 1)[0]
                if lang in const.LANG.VALUES:
                    return const.LANG.VALUES[lang]
                else:
                    logging.warning('UNKNOWN lang %s' % value)
                    return config.DEFAULT_LANG

        _01_VALUES = ['0', '1', 0, 1]

        def validate_jail_broken(value):
            return int(value) if value in _01_VALUES else 0

        def validate_root(value):
            return int(value) if value in _01_VALUES else 0

        def validate_screen_dpi(value):
            try:
                floatValue = float(value)
                return floatValue
            except (ValueError, TypeError):
                return False

        def validate_session_id(value):
            if value is None:
                return value
            if len(value) != const.ACCOUNT.SESSION_ID_LENGTH:
                logging.warning('SESSION_ID INVALID: %s' % value)
                return False
            return value

        value = _get_header(key)
        func = locals().get('validate_' + key.lower())
        if func is not None:
            return func(value), value
        else:
            return False if value is None else value, value

    def deco(old_view):
        @wraps(old_view)
        def new_view(*args, **kwargs):
            header_dict = {}

            system = convert_system(_get_header('SYSTEM_TYPE'))
            if is_apple(system):
                required = IOS_REQUIRED
                optional = IOS_OPTIONAL
            elif is_android(system):
                required = ANDROID_REQUIRED
                optional = ANDROID_OPTIONAL
            elif system == const.SYSTEM.WIN:
                required = WIN_REQUIRED
                optional = WIN_OPTIONAL
            else:
                logging.info('BAD HEADER: invalid system: %s', system)
                return JsonResponse(const.API_ERROR.BAD_HEADER)

            for key in required:
                validated, value = validate(key)
                if validated is False:
                    logging.info('BAD HEADER: %s -> %s' % (key, value))
                    return JsonResponse(const.API_ERROR.BAD_HEADER)
                else:
                    header_dict[key] = validated

            for key in optional:
                validated, value = validate(key)
                header_dict[key] = '' if validated is False else validated

            header_dict['real_locale'] = _get_header('LOCALE')

            kwargs['header'] = header_dict
            return old_view(*args, **kwargs)

        return new_view

    return deco


def decrypt_gcm_request():
    """
    去掉uumkit.framework.decrypt_gcm_request()中的base64
    """
    if not request.data:
        request.decrypted_json = request.get_json(True, True)
        return

    try:
        decrypted = aes.aes_gcm_decrypt(request.data, config.SIGN.KEY)
        decrypted = zlib.decompress(decrypted, 47)
    except Exception as e:
        logging.error('request decrypress FAILED: %s' % e)
        raise CrypressException()

    try:
        request.decrypted_data = decrypted
        request.decrypted_json = json.loads(util.str_(decrypted))
    except ValueError as e:
        logging.error('request loads FAILED: %s' % e)
        raise JsonException()


def encrypt_gcm_response(response, status_code=200):
    """
    去掉uumkit.framework.encrypt_gcm_response()中的base64
    """
    if isinstance(response, Response):
        raw = response.get_data()
        headers = response.headers
    else:
        raw = response
        headers = {}

    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, 31)
    s = StringIO()
    s.write(util.str_(raw))
    encoded = s.getvalue().encode()
    compressed = compressor.compress(encoded) + compressor.flush()
    s.close()

    encrypted = aes.aes_gcm_encrypt(util.bytes_(compressed), config.SIGN.KEY)

    headers['Encryption'] = True
    headers['Content-Type'] = 'application/octet-stream'
    resp = make_response((encrypted, status_code, headers))
    return resp


def safe_encrypt_response(response):
    assert isinstance(response, Response)  # 限制endpoint返回格式

    if config.DEBUG and request.headers.get(const.HEADER.NO_DECRYPT):
        return response

    if request.headers.get(const.HEADER.DEVICE_ID):
        try:
            crypted = encrypt_gcm_response(response, status_code=response.status)
            crypted.decrypted_data = response.get_data()
            return crypted
        except Exception:
            logging.exception('encrypt_response error')

    return response


def cryptgcm():
    """
    使用 AES_GCM 方式进行加解密
    先对请求 body 解密再解压缩，再对响应 body 压缩再加密
    """

    # fmt: off
    def deco(old_view):
        @wraps(old_view)
        def new_view(*args, **kwargs):
            # fmt: on
            if config.DEBUG and request.headers.get(const.HEADER.NO_DECRYPT):
                request.decrypted_json = request.get_json(True, True)
                return old_view(*args, **kwargs)
            else:
                try:
                    decrypt_gcm_request()
                except CrypressException:
                    return JsonResponse(const.API_ERROR.PARAMS_DECRYPT_FAILED)
                except JsonException:
                    return JsonResponse(const.API_ERROR.BAD_PARAMS)
                except KeyError:
                    return JsonResponse(const.API_ERROR.BAD_PARAMS)
                else:
                    ret = old_view(*args, **kwargs)
                    return safe_encrypt_response(ret)
        return new_view
    return deco
'''

class Parser(FlaskParser):
    def _raw_load_json(self, req):
        if hasattr(req, 'decrypted_json'):
            return req.decrypted_json
        else:
            return super()._raw_load_json(req)


parser = Parser()
