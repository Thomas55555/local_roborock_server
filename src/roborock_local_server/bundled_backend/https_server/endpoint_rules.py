"""Declarative endpoint behavior rules for the FastAPI HTTPS server."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import gzip
import hashlib
import json
import re
import time
from typing import Any, Callable, Sequence
from urllib.parse import quote

from shared.context import ServerContext
from shared.http_helpers import wrap_response
from shared.routine_runner import RoutineExecutionError, RoutineRunner

RouteMatcher = Callable[..., bool]
RouteResponseFactory = Callable[[ServerContext, dict[str, list[str]], dict[str, list[str]], str], dict[str, Any]]

_LOGIN_SIGN_KEY = "DnNAYQHCVFIdHSKx"
_LOGIN_CAPTCHA_CONTENT = (
    "mRHPW0lkX2AwKYqCEKDEiq6AAUd6T1sL+RQQUbSWLiVnyBfv2t4+IllIDtglVdE1kXCSMSW2SugV02sVbXslxDu4c9uZ53lUsGhmuJSUj1w="
)
_REGION_COUNTRY_CODE = {
    "US": "1",
    "CN": "86",
    "EU": "49",
    "RU": "7",
}
_WEB_API_INVENTORY_FILE = "web_api_inventory.json"
_WEB_API_FULL_SNAPSHOT_SUFFIX = "_full_snapshot.json"
_DEFAULT_HOME_NAME = "Local Home"
_DEFAULT_TIMEZONE = "America/New_York"
_RSA_OAEP_SHA1_MAX_PLAINTEXT = 214
_DEFAULT_AVATAR_URL = "https://files.roborock.com/iot/default_avatar.png"
_APP_CONFIG_COMMON_DATA = {
    "version": "4.41.04",
    "url": "itms-apps://itunes.apple.com/cn/app/id1462875428?mt=8",
    "required": 0,
    "description": "<p><br></p>",
    "minimumVersion": "0.0.0",
    "mainPictureInfoList": [
        {
            "darkModePic": "https://files.roborock.com/iot/doc/bbecbae006b940eab34d200ba809bb72.png",
            "lightModePic": "https://files.roborock.com/iot/doc/a35d5dfcd6eb41e69dab160fe12f059f.png",
        },
        {
            "darkModePic": "https://files.roborock.com/iot/doc/588414a901d645058c9dce93b5f891c3.png",
            "lightModePic": "https://files.roborock.com/iot/doc/e38de51323a743628f094358611c6b0d.png",
        },
        {
            "darkModePic": "https://files.roborock.com/iot/doc/576cfc12bed843c9b45bffabceb07259.png",
            "lightModePic": "https://files.roborock.com/iot/doc/de2f035553f24795a5699279193d312a.png",
        },
    ],
}
_APP_CONFIG_V2_EXTRAS = {
    "entryConfigs": [
        {"name": "MEMBER_CENTER", "enabled": False, "target": None},
        {"name": "SERVICE_CENTER", "enabled": False, "target": None},
    ],
    "pluginEntryConfigs": {"ASSISTANT": False},
}
_APP_FEATURE_PLUGIN_LIST = [
    {
        "moduleType": "DEVICE_PAIRING",
        "version": 120,
        "apiLevel": 10028,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/0e2aad7a7c0b4721ac06c415b48bd0a8.zip",
        "pluginLevel": 3001,
        "scope": None,
    },
    {
        "moduleType": "PERSONAL_CENTER",
        "version": 292,
        "apiLevel": 10044,
        "url": "https://app-files.roborock.com/iot/plugin/ddb433cf4f2b43c9b553aea3ace73f4e.zip",
        "pluginLevel": 3002,
        "scope": None,
    },
]
_MODEL_PRODUCT_ID_OVERRIDES = {
    "roborock.vacuum.a87": 110,
    "roborock.vacuum.a15": 23,
    "roborock.vacuum.sc05": 10001,
}
_CATEGORY_PLUGIN_LIST = [
    {
        "categoryId": 1,
        "category": "robot.vacuum.cleaner",
        "md5": None,
        "version": 2050,
        "apiLevel": 10028,
        "url": "https://files.roborock.com/iot/plugin/979bb22f91a24f10a8bafe232b4fb5ee.zip",
        "pluginLevel": 1,
        "scope": None,
    },
    {
        "categoryId": 2,
        "category": "roborock.wetdryvac",
        "md5": None,
        "version": 1024,
        "apiLevel": 10028,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/10320c51139848e9ade1e6bd231e15c8.zip",
        "pluginLevel": 1,
        "scope": None,
    },
    {
        "categoryId": 3,
        "category": "roborock.wm",
        "md5": None,
        "version": 1014,
        "apiLevel": 10028,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/7f2a3e398aa54427afb48461f69a1a8c.zip",
        "pluginLevel": 1,
        "scope": None,
    },
]
_APPPLUGIN_LIST = [
    {
        "version": 6058,
        "url": "https://files.roborock.com/iot/plugin/ea53983b82e948638904d9154bb7f474.zip",
        "pluginLevel": 3001,
        "productid": 110,
        "apilevel": 10028,
    },
    {
        "version": 5208,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/7cf4eb4c705c420483741189be389927.zip",
        "pluginLevel": 3001,
        "productid": 23,
        "apilevel": 10028,
    },
    {
        "version": 90,
        "url": "https://rrpkg-us.roborock.com/iot/plugin/019b4e083fbe7f81a28d79756be6f0ed.zip",
        "pluginLevel": 3001,
        "productid": 10001,
        "apilevel": 10028,
    },
]
_COUNTRY_LIST_JSON = {
    "countries": [
        {
            "abbr": "US",
            "code": "1",
            "region": "US",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
        {
            "abbr": "CN",
            "code": "86",
            "region": "CN",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
        {
            "abbr": "DE",
            "code": "49",
            "region": "EU",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
        {
            "abbr": "RU",
            "code": "7",
            "region": "RU",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
    ],
    "i18n": [
        {
            "lang": "en",
            "names": [
                {"abbr": "US", "name": "United States", "spell": "unitedstates"},
                {"abbr": "CN", "name": "China", "spell": "china"},
                {"abbr": "DE", "name": "Germany", "spell": "germany"},
                {"abbr": "RU", "name": "Russia", "spell": "russia"},
            ],
        }
    ],
}
_COUNTRY_LIST_D = base64.b64encode(gzip.compress(json.dumps(_COUNTRY_LIST_JSON, separators=(",", ":")).encode())).decode()
_AGREEMENT_LATEST_DATA = {
    "userAgreement": {
        "version": "16.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/7f65ba7da3ab4e0db1177c366a03d06e.html",
            "en": "https://files.roborock.com/iot/doc/8765be2db5dd4b87bac8ba82ba1b6878.html",
        },
        "popupText": None,
    },
    "privacyProtocol": {
        "version": "17.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/e8143aeb64544008b864e1b06cde4543.html",
            "en": "https://files.roborock.com/iot/doc/d1945f29e9794bdba80496a998298751.html",
        },
        "popupText": None,
    },
    "personalInfoCol": {
        "version": "2.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/1df929732c104dcc9f0f489d5b368cc9.html",
            "en": "https://files.roborock.com/iot/doc/d24f84ac2f3d4b50a9897d64b4faacbd.html",
        },
        "popupText": None,
    },
    "thirdPartyInfoShare": {
        "version": "3.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/23f480bb58e14db593639878095249a6.html",
            "en": "https://files.roborock.com/iot/doc/dd725a4e900a47b382897a59da09aed5.html",
        },
        "popupText": None,
    },
    "improvementPlan": {
        "version": "1.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/1184a5a566c24bd1b520e4063cae1a14.html",
            "en": "https://files.roborock.com/iot/doc/3e754f53d8934487ad448a5defec6caa.html",
        },
        "popupText": None,
    },
}


def _ok(data: Any) -> dict[str, Any]:
    # Match upstream auth/iot envelope exactly for app login flow.
    return {"code": 200, "msg": "success", "data": data}


def _match_login_ml_c(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/ml/c"


def _match_login_key_sign(path: str) -> bool:
    return path.rstrip("/") == "/api/v3/key/sign"


def _match_login_key_captcha(path: str) -> bool:
    return path.rstrip("/") == "/api/v4/key/captcha"


def _match_login_email_code_send(path: str) -> bool:
    return path.rstrip("/") in {
        "/api/v5/email/code/send",
        "/api/v4/email/code/send",
        "/api/v1/sendEmailCode",
    }


def _match_login_sms_code_send(path: str) -> bool:
    return path.rstrip("/") in {
        "/api/v3/sms/sendCode",
        "/api/v4/sms/code/send",
        "/api/v5/sms/code/send",
        "/api/v1/sendSmsCode",
    }


def _match_login_code_validate(path: str) -> bool:
    return path.rstrip("/") in {
        "/api/v4/email/code/validate",
        "/api/v4/sms/code/validate",
        "/api/v5/email/code/validate",
        "/api/v5/sms/code/validate",
        "/api/v1/validateEmailCode",
        "/api/v1/validateSmsCode",
    }


def _match_login_code_submit(path: str) -> bool:
    clean = path.rstrip("/")
    if clean in {
        "/api/v4/auth/email/login/code",
        "/api/v4/auth/phone/login/code",
        "/api/v4/auth/mobile/login/code",
        "/api/v5/auth/email/login/code",
        "/api/v5/auth/phone/login/code",
        "/api/v5/auth/mobile/login/code",
        "/api/v1/loginWithCode",
    }:
        return True
    return clean.startswith("/api/") and "/auth/" in clean and clean.endswith("/login/code")


def _match_login_password_submit(path: str) -> bool:
    clean = path.rstrip("/")
    if clean in {
        "/api/v3/auth/email/login",
        "/api/v3/auth/phone/login",
        "/api/v3/auth/mobile/login",
        "/api/v5/auth/email/login/pwd",
        "/api/v5/auth/phone/login/pwd",
        "/api/v5/auth/mobile/login/pwd",
        "/api/v1/login",
    }:
        return True
    return clean.startswith("/api/") and "/auth/" in clean and (
        clean.endswith("/login") or clean.endswith("/login/pwd")
    )


def _match_login_password_reset(path: str) -> bool:
    return path.rstrip("/") in {
        "/api/v5/user/password/mobile/reset",
        "/api/v5/user/password/email/reset",
    }


def _match_country_version(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/country/version"


def _match_country_list(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/country/list"


def _match_agreement_latest(path: str) -> bool:
    return path.rstrip("/") == "/api/v4/app/agreement/latest"


def _match_get_url_by_email(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/getUrlByEmail"


def _match_get_home_detail(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/getHomeDetail"


def _match_user_info(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/userInfo"


def _match_app_config(path: str) -> bool:
    return path.rstrip("/") in {"/api/v1/appconfig", "/api/v2/appconfig"}


def _match_app_feature_plugin(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appfeatureplugin"


def _match_home_devices_order(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/api/v1/home/[^/]+/devices/order", clean))


def _match_user_roles(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/user/roles"


def _match_logout(path: str, method: str = "GET") -> bool:
    return method.upper() == "POST" and path.rstrip("/") == "/api/v1/logout"


def _match_get_home_data(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/(?:(?:v2|v3)/)?user/homes/[^/]+", clean))


def _match_get_home_rooms(path: str) -> bool:
    clean = path.rstrip("/")
    # python-roborock currently has a malformed /rooms path for get_rooms; support both.
    return bool(re.fullmatch(r"/user/homes/[^/]+/rooms(?:[^/]*)", clean))


def _match_post_home_rooms(path: str, method: str = "GET") -> bool:
    return method.upper() == "POST" and _match_get_home_rooms(path)


def _match_post_scene_create(path: str, method: str = "GET") -> bool:
    return method.upper() == "POST" and path.rstrip("/") == "/v2/user/scene"


def _match_get_scenes(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/scene/device/[^/]+", clean))


def _match_get_home_scenes(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/scene/home/[^/]+", clean))


def _match_get_scene_order(path: str) -> bool:
    return path.rstrip("/") == "/user/scene/order"


def _match_execute_scene(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/scene/\d+/execute", clean))


def _match_put_scene_name(path: str, method: str = "GET") -> bool:
    clean = path.rstrip("/")
    return method.upper() == "PUT" and bool(re.fullmatch(r"/user/scene/\d+/name", clean))


def _match_put_scene_param(path: str, method: str = "GET") -> bool:
    clean = path.rstrip("/")
    return method.upper() == "PUT" and bool(re.fullmatch(r"/user/scene/\d+/param", clean))


def _match_get_device(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/devices/[^/]+", clean))


def _match_get_device_extra(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/devices/[^/]+/extra", clean))


def _match_get_schedules(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/devices/[^/]+/jobs", clean))


def _match_post_app_info(path: str) -> bool:
    return path.rstrip("/") == "/user/app/info"


def _match_get_inbox_latest(path: str) -> bool:
    return path.rstrip("/") == "/user/inbox/latest"


def _match_get_products(path: str) -> bool:
    return path.rstrip("/") in {"/api/v4/product", "/api/v5/product"}


def _match_download_code(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appplugin"


def _match_download_category_code(path: str) -> bool:
    clean = path.rstrip("/")
    return clean in {"/api/v1/plugins", "api/v1/plugins"}


def _match_add_device(path: str) -> bool:
    return path.rstrip("/") == "/user/devices/newadd"


def _request_host_override(query_params: dict[str, list[str]]) -> str:
    values = query_params.get("__host") or []
    for value in values:
        candidate = str(value or "").strip()
        if candidate:
            return candidate.split(":", 1)[0].strip()
    return ""


def _build_login_ml_c(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok({"r": False})


def _build_login_key_sign(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok({"k": _LOGIN_SIGN_KEY})


def _build_login_key_captcha(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok({"type": "RECAPTCHA", "content": _LOGIN_CAPTCHA_CONTENT})


def _build_login_email_code_send(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    # Explicit non-null payload keeps legacy/new app code paths happy.
    return _ok({"sent": True, "validForSec": 300})


def _default_country_code_for_region(region: str) -> str:
    return _REGION_COUNTRY_CODE.get(region.upper(), "1")


def _cloud_snapshot_path(ctx: ServerContext):
    inventory_path = ctx.http_jsonl.parent / _WEB_API_INVENTORY_FILE
    return inventory_path.with_name(f"{inventory_path.stem}{_WEB_API_FULL_SNAPSHOT_SUFFIX}")


def _current_server_urls(ctx: ServerContext) -> tuple[str, str, str]:
    api_url = f"https://{ctx.api_host}"
    mqtt_url = f"ssl://{ctx.mqtt_host}:{ctx.mqtt_tls_port}"
    wood_url = f"https://{ctx.wood_host}"
    return api_url, mqtt_url, wood_url


def _with_current_server_urls(ctx: ServerContext, cloud_user_data: dict[str, Any]) -> dict[str, Any]:
    api_url, mqtt_url, wood_url = _current_server_urls(ctx)
    patched_user_data = dict(cloud_user_data)

    rriot_value = patched_user_data.get("rriot")
    if isinstance(rriot_value, dict):
        rriot = dict(rriot_value)
        ref_value = rriot.get("r")
        ref = dict(ref_value) if isinstance(ref_value, dict) else {}
        ref.update({"a": api_url, "m": mqtt_url, "l": wood_url})
        rriot["r"] = ref
        patched_user_data["rriot"] = rriot

    servers_value = patched_user_data.get("servers")
    servers = dict(servers_value) if isinstance(servers_value, dict) else {}
    servers.update(
        {
            "apiUrl": api_url,
            "mqttUrl": mqtt_url,
            "woodUrl": wood_url,
            "api_url": api_url,
            "mqtt_url": mqtt_url,
            "wood_url": wood_url,
            "a": api_url,
            "m": mqtt_url,
            "l": wood_url,
        }
    )
    patched_user_data["servers"] = servers
    return patched_user_data


def _load_cloud_full_snapshot(ctx: ServerContext) -> dict[str, Any] | None:
    full_snapshot_path = _cloud_snapshot_path(ctx)
    if not full_snapshot_path.exists():
        return None
    try:
        parsed = json.loads(full_snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _load_cloud_user_data(ctx: ServerContext) -> dict[str, Any] | None:
    parsed = _load_cloud_full_snapshot(ctx)
    if not isinstance(parsed, dict):
        return None
    user_data = parsed.get("user_data")
    if not isinstance(user_data, dict):
        return None
    return _with_current_server_urls(ctx, user_data)


def _load_cloud_home_data(ctx: ServerContext) -> dict[str, Any] | None:
    parsed = _load_cloud_full_snapshot(ctx)
    if not isinstance(parsed, dict):
        return None
    home_data = parsed.get("home_data")
    return home_data if isinstance(home_data, dict) else None


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _missing_cloud_login_fields(cloud_user_data: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    if cloud_user_data.get("uid") is None:
        missing.append("uid")
    if not _is_non_empty_string(cloud_user_data.get("token")):
        missing.append("token")
    if not _is_non_empty_string(cloud_user_data.get("rruid")):
        missing.append("rruid")
    rriot = cloud_user_data.get("rriot")
    if not isinstance(rriot, dict):
        missing.append("rriot")
        return missing
    for key in ("u", "s", "h", "k"):
        if not _is_non_empty_string(rriot.get(key)):
            missing.append(f"rriot.{key}")
    ref = rriot.get("r")
    if not isinstance(ref, dict):
        missing.append("rriot.r")
        return missing
    for key in ("r", "a", "m", "l"):
        if not _is_non_empty_string(ref.get(key)):
            missing.append(f"rriot.r.{key}")
    return missing


def _cloud_login_data_required_response(
    ctx: ServerContext,
    *,
    reason: str,
    missing_fields: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "reason": reason,
        "hint": "Fetch cloud data once via /ui/api/cloud/request-code and /ui/api/cloud/submit-code, then retry login.",
        "required_snapshot": str(_cloud_snapshot_path(ctx)),
    }
    if missing_fields:
        payload["missing_fields"] = missing_fields
    return {"code": 41201, "msg": "cloud_user_data_required", "data": payload}


def _build_login_data_response(ctx: ServerContext) -> dict[str, Any]:
    cloud_user_data = _load_cloud_user_data(ctx)
    if cloud_user_data is None:
        return _cloud_login_data_required_response(ctx, reason="missing_snapshot_or_user_data")
    missing_fields = _missing_cloud_login_fields(cloud_user_data)
    if missing_fields:
        return _cloud_login_data_required_response(
            ctx,
            reason="incomplete_cloud_user_data",
            missing_fields=missing_fields,
        )
    return _ok(cloud_user_data)


def _build_login_sms_code_send(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    # Explicit non-null payload keeps legacy/new app code paths happy.
    return _ok({"sent": True, "validForSec": 300})


def _build_login_code_validate(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    # Any code is accepted for local interception workflows.
    return _ok({"valid": True})


def _build_login_code_submit(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    return _build_login_data_response(ctx)


def _build_login_password_submit(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    return _build_login_data_response(ctx)


def _build_login_password_reset(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok(None)


def _build_country_version(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    # Keep version low so clients can continue using inbuilt country tables when preferred.
    return _ok({"v": 0})


def _build_country_list(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok({"d": _COUNTRY_LIST_D})


def _build_agreement_latest(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok(_AGREEMENT_LATEST_DATA)


def _first_non_empty(values: Sequence[str]) -> str:
    for value in values:
        if value:
            return value
    return ""


def _get_value(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, str) and value.strip() == "":
            continue
        return value
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _extract_explicit_did(query_params: dict[str, list[str]], body_params: dict[str, list[str]]) -> str:
    return _first_non_empty(
        (query_params.get("did") or [])
        + (query_params.get("d") or [])
        + (query_params.get("duid") or [])
        + (body_params.get("did") or [])
        + (body_params.get("d") or [])
        + (body_params.get("duid") or [])
    )


def _stable_int(seed: str) -> int:
    return int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12], 16)


def _default_home_id(ctx: ServerContext) -> int:
    return _stable_int(f"{ctx.duid}:home")


def _default_product_name(model: str) -> str:
    short_model = model.split(".")[-1].upper() if model else "VACUUM"
    return f"Roborock {short_model}"


def _routine_runner_for_context(ctx: ServerContext) -> RoutineRunner:
    runner = getattr(ctx, "_routine_runner", None)
    if runner is None:
        runner = RoutineRunner(ctx)
        setattr(ctx, "_routine_runner", runner)
    return runner


def _runtime_connected_identity_set(ctx: ServerContext) -> tuple[set[str], bool]:
    """Return runtime-connected device identities keyed by DUID/DID."""
    runtime_state = getattr(ctx, "runtime_state", None)
    if runtime_state is None:
        return set(), False
    runtime_credentials = getattr(ctx, "runtime_credentials", None)

    try:
        snapshot = runtime_state.vacuum_snapshot()
        key_models_by_did = runtime_state.key_models_by_did()
    except Exception:
        return set(), False

    connected_ids: set[str] = set()
    connected_models: set[str] = set()
    for vac in snapshot:
        if not isinstance(vac, dict):
            continue
        if not _as_bool(vac.get("connected"), False):
            continue
        for key in ("duid", "did"):
            value = vac.get(key)
            if value is None:
                continue
            normalized = str(value).strip()
            if normalized:
                connected_ids.add(normalized)
        did = str(vac.get("did") or "").strip()
        if did:
            if runtime_credentials is not None:
                credential_device = runtime_credentials.resolve_device(did=did)
                if credential_device is not None:
                    credential_duid = str(credential_device.get("duid") or "").strip()
                    if credential_duid:
                        connected_ids.add(credential_duid)
            model_hint = str(vac.get("key_model") or key_models_by_did.get(did) or "").strip().lower()
            if model_hint:
                connected_models.add(model_hint)

    # Runtime MQTT topics often identify devices by numeric DID while cloud
    # inventory uses DUID. Link connected runtime devices back to inventory
    # entries via unique model when possible.
    inventory = _load_inventory(ctx)
    inventory_sources: list[dict[str, Any]] = []
    for source_key in ("devices", "received_devices", "receivedDevices"):
        source_list = inventory.get(source_key)
        if not isinstance(source_list, list):
            continue
        for raw in source_list:
            if isinstance(raw, dict):
                inventory_sources.append(raw)

    model_counts: dict[str, int] = {}
    for raw in inventory_sources:
        model = str(_get_value(raw, "model", default="")).strip().lower()
        if not model:
            continue
        model_counts[model] = model_counts.get(model, 0) + 1

    for raw in inventory_sources:
        model = str(_get_value(raw, "model", default="")).strip().lower()
        if not model or model_counts.get(model, 0) != 1 or model not in connected_models:
            continue
        inventory_duid = str(_get_value(raw, "duid", "did", "device_id", default="")).strip()
        if inventory_duid:
            connected_ids.add(inventory_duid)
    return connected_ids, bool(connected_ids)


def _runtime_online_for_device(
    raw_item: dict[str, Any],
    *,
    runtime_connected_ids: set[str],
) -> bool:
    """Decide if a device should be marked online from runtime connectivity."""
    for key in ("duid", "did", "device_did", "deviceDid", "device_id", "deviceId"):
        value = raw_item.get(key)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized and normalized in runtime_connected_ids:
            return True

    return False


def _load_inventory(ctx: ServerContext) -> dict[str, Any]:
    path = ctx.http_jsonl.parent / _WEB_API_INVENTORY_FILE
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _write_inventory(ctx: ServerContext, inventory: dict[str, Any]) -> None:
    path = ctx.http_jsonl.parent / _WEB_API_INVENTORY_FILE
    try:
        path.write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return


def _scene_request_from_body(body_params: dict[str, list[str]]) -> dict[str, Any]:
    scene_request = _parse_json_body_params(body_params)
    if scene_request:
        return scene_request
    return {
        key: values[0] if len(values) == 1 else list(values)
        for key, values in body_params.items()
        if not key.startswith("__") and values != [""]
    }


def _scene_param_json_string(param_payload: dict[str, Any]) -> str:
    return json.dumps(param_payload, ensure_ascii=False, separators=(",", ":"))


def _inventory_home_id(ctx: ServerContext, inventory: dict[str, Any]) -> int:
    home_value = inventory.get("home")
    home = home_value if isinstance(home_value, dict) else {}
    return _as_int(
        _get_value(home, "id", "home_id", "rrHomeId", "rr_home_id", default=_default_home_id(ctx)),
        _default_home_id(ctx),
    )


def _scene_zone_key(tid: str, zid: int) -> tuple[str, int] | None:
    normalized_tid = str(tid or "").strip()
    if not normalized_tid or zid < 0:
        return None
    return normalized_tid, zid


def _scene_zone_range(raw_zone: dict[str, Any]) -> list[int] | None:
    range_value = raw_zone.get("range")
    if not isinstance(range_value, list) or len(range_value) < 4:
        return None
    return [_as_int(value, 0) for value in range_value[:4]]


def _merge_scene_zone_ranges_from_request(
    zone_ranges: dict[tuple[str, int], list[int]],
    *,
    params: Any,
    tids_filter: set[str] | None,
) -> None:
    if not isinstance(params, dict):
        return
    data = params.get("data")
    if not isinstance(data, list):
        return
    for entry in data:
        if not isinstance(entry, dict):
            continue
        tid = str(entry.get("tid") or "").strip()
        if tids_filter and tid not in tids_filter:
            continue
        zones = entry.get("zones")
        if not isinstance(zones, list):
            continue
        for zone in zones:
            if not isinstance(zone, dict):
                continue
            range_value = _scene_zone_range(zone)
            key = _scene_zone_key(tid, _as_int(zone.get("zid"), -1))
            if key is None or range_value is None:
                continue
            zone_ranges[key] = range_value


def _merge_scene_zone_ranges_from_response(
    zone_ranges: dict[tuple[str, int], list[int]],
    *,
    request_params: Any,
    result: Any,
    tids_filter: set[str] | None,
) -> None:
    if not isinstance(request_params, dict) or not isinstance(result, list):
        return
    request_data = request_params.get("data")
    if not isinstance(request_data, list):
        return
    for request_entry, result_entry in zip(request_data, result):
        if not isinstance(request_entry, dict) or not isinstance(result_entry, dict):
            continue
        tid = str(result_entry.get("tid") or request_entry.get("tid") or "").strip()
        if tids_filter and tid not in tids_filter:
            continue
        request_zones = request_entry.get("zones")
        result_zones = result_entry.get("zones")
        if not isinstance(request_zones, list) or not isinstance(result_zones, list):
            continue
        for index, request_zone in enumerate(request_zones):
            if not isinstance(request_zone, dict):
                continue
            result_zone = result_zones[index] if index < len(result_zones) and isinstance(result_zones[index], dict) else {}
            range_value = _scene_zone_range(request_zone)
            key = _scene_zone_key(tid, _as_int(result_zone.get("zid", request_zone.get("zid")), -1))
            if key is None or range_value is None:
                continue
            zone_ranges[key] = range_value


def _scene_zone_ranges_from_mqtt(
    ctx: ServerContext,
    *,
    tids_filter: set[str] | None = None,
) -> dict[tuple[str, int], list[int]]:
    path = ctx.mqtt_jsonl
    if not path.exists():
        return {}
    zone_ranges: dict[tuple[str, int], list[int]] = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                decoded_messages = entry.get("decoded_messages")
                if not isinstance(decoded_messages, list):
                    continue
                for decoded in decoded_messages:
                    if not isinstance(decoded, dict):
                        continue
                    rpc = decoded.get("rpc")
                    if isinstance(rpc, dict) and str(rpc.get("method") or "").strip() == "set_scenes_zones":
                        _merge_scene_zone_ranges_from_request(
                            zone_ranges,
                            params=rpc.get("params"),
                            tids_filter=tids_filter,
                        )
                    response_to = decoded.get("response_to")
                    if isinstance(response_to, dict) and str(response_to.get("request_method") or "").strip() == "set_scenes_zones":
                        _merge_scene_zone_ranges_from_response(
                            zone_ranges,
                            request_params=response_to.get("request_params"),
                            result=response_to.get("result"),
                            tids_filter=tids_filter,
                        )
    except OSError:
        return {}
    return zone_ranges


def _scene_zone_tids(param_payload: dict[str, Any]) -> set[str]:
    action = param_payload.get("action")
    items = action.get("items") if isinstance(action, dict) else []
    tids: set[str] = set()
    if not isinstance(items, list):
        return tids
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_param = item.get("param")
        if isinstance(raw_param, str):
            try:
                inner = json.loads(raw_param)
            except json.JSONDecodeError:
                continue
        elif isinstance(raw_param, dict):
            inner = raw_param
        else:
            continue
        if not isinstance(inner, dict) or str(inner.get("method") or "").strip() != "do_scenes_zones":
            continue
        params = inner.get("params")
        data = params.get("data") if isinstance(params, dict) else []
        if not isinstance(data, list):
            continue
        for entry in data:
            if not isinstance(entry, dict):
                continue
            tid = str(entry.get("tid") or "").strip()
            if tid:
                tids.add(tid)
    return tids


def _hydrate_scene_param_with_zone_ranges(
    ctx: ServerContext,
    param_payload: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    tids = _scene_zone_tids(param_payload)
    if not tids:
        return param_payload, False
    zone_ranges = _scene_zone_ranges_from_mqtt(ctx, tids_filter=tids)
    if not zone_ranges:
        return param_payload, False
    try:
        hydrated_payload = json.loads(_scene_param_json_string(param_payload))
    except (TypeError, ValueError):
        return param_payload, False

    changed = False
    action = hydrated_payload.get("action")
    items = action.get("items") if isinstance(action, dict) else []
    if not isinstance(items, list):
        return param_payload, False
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_param = item.get("param")
        nested_as_string = isinstance(raw_param, str)
        if nested_as_string:
            try:
                nested = json.loads(raw_param)
            except json.JSONDecodeError:
                continue
        elif isinstance(raw_param, dict):
            nested = dict(raw_param)
        else:
            continue
        if not isinstance(nested, dict) or str(nested.get("method") or "").strip() != "do_scenes_zones":
            continue
        params = nested.get("params")
        data = params.get("data") if isinstance(params, dict) else []
        if not isinstance(data, list):
            continue

        item_changed = False
        new_data: list[Any] = []
        for entry in data:
            if not isinstance(entry, dict):
                new_data.append(entry)
                continue
            tid = str(entry.get("tid") or "").strip()
            zones = entry.get("zones")
            if not isinstance(zones, list):
                new_data.append(entry)
                continue
            new_entry = dict(entry)
            new_zones: list[Any] = []
            entry_changed = False
            for zone in zones:
                if not isinstance(zone, dict):
                    new_zones.append(zone)
                    continue
                range_value = zone_ranges.get((tid, _as_int(zone.get("zid"), -1)))
                if range_value is None:
                    new_zones.append(zone)
                    continue
                new_zone = dict(zone)
                if new_zone.get("range") != range_value:
                    new_zone["range"] = list(range_value)
                    entry_changed = True
                new_zones.append(new_zone)
            if entry_changed:
                new_entry["zones"] = new_zones
                item_changed = True
            new_data.append(new_entry)
        if not item_changed:
            continue
        new_params = dict(params)
        new_params["data"] = new_data
        nested["params"] = new_params
        item["param"] = _scene_param_json_string(nested) if nested_as_string else nested
        changed = True
    return (hydrated_payload if changed else param_payload), changed


def _replace_inventory_scene(
    ctx: ServerContext,
    *,
    scene_id: int,
    scene_updater: Callable[[dict[str, Any], dict[str, Any]], None],
) -> tuple[dict[str, Any], int]:
    inventory = _load_inventory(ctx)
    if not isinstance(inventory, dict):
        inventory = {}

    scenes_source = inventory.get("scenes")
    scenes = [dict(scene) for scene in scenes_source if isinstance(scene, dict)] if isinstance(scenes_source, list) else []
    updated_scene: dict[str, Any] | None = None
    for index, scene in enumerate(scenes):
        if _as_int(_get_value(scene, "id", default=0), 0) != scene_id:
            continue
        candidate = dict(scene)
        scene_updater(candidate, inventory)
        scenes[index] = candidate
        updated_scene = candidate
        break

    if updated_scene is None:
        raise RoutineExecutionError(f"Scene {scene_id} not found")

    inventory["scenes"] = scenes
    home_id = _inventory_home_id(ctx, inventory)
    inventory["home_scenes"] = [
        _build_scene_payload(scene, home_id=home_id, include_device_context=True)
        for scene in scenes
        if isinstance(scene, dict)
    ]
    _write_inventory(ctx, inventory)
    return updated_scene, home_id


def _hydrate_inventory_scene_ranges(ctx: ServerContext, scene: dict[str, Any]) -> dict[str, Any]:
    scene_id = _as_int(_get_value(scene, "id", default=0), 0)
    if scene_id <= 0:
        return scene
    param_payload = _scene_param_payload(scene)
    hydrated_payload, changed = _hydrate_scene_param_with_zone_ranges(ctx, param_payload)
    if not changed:
        return scene

    def apply_update(updated_scene: dict[str, Any], inventory: dict[str, Any]) -> None:
        _ = inventory
        updated_scene["param"] = _scene_param_json_string(hydrated_payload)

    updated_scene, _ = _replace_inventory_scene(ctx, scene_id=scene_id, scene_updater=apply_update)
    return updated_scene


def _parse_json_body_params(body_params: dict[str, list[str]]) -> dict[str, Any]:
    raw_candidates = list(body_params.get("__json") or [])
    if not raw_candidates and len(body_params) == 1:
        raw_key, raw_values = next(iter(body_params.items()))
        if raw_values == [""] and str(raw_key).lstrip().startswith(("{", "[")):
            raw_candidates.append(str(raw_key))

    for raw_candidate in raw_candidates:
        try:
            parsed = json.loads(raw_candidate)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _extract_home_id_from_rooms_path(ctx: ServerContext, clean_path: str) -> int:
    match = re.fullmatch(r"/user/homes/([^/]+)/rooms(?:[^/]*)", clean_path.rstrip("/"))
    if match is None:
        return _default_home_id(ctx)
    return _as_int(match.group(1), _default_home_id(ctx))


def _upsert_inventory_room(ctx: ServerContext, *, home_id: int, room_name: str) -> tuple[dict[str, Any], bool]:
    inventory = _load_inventory(ctx)
    if not isinstance(inventory, dict):
        inventory = {}

    home_value = inventory.get("home")
    home = dict(home_value) if isinstance(home_value, dict) else {}
    rooms_source = home.get("rooms")
    if not isinstance(rooms_source, list):
        rooms_source = inventory.get("rooms")
    rooms = _normalize_rooms({"home": {"rooms": rooms_source}}) if isinstance(rooms_source, list) else []

    normalized_name = room_name.strip() or f"Room {len(rooms) + 1}"
    existing_room = next(
        (room for room in rooms if str(room.get("name") or "").strip().casefold() == normalized_name.casefold()),
        None,
    )
    if existing_room is not None:
        room_payload = {"id": _as_int(existing_room.get("id"), 0), "name": str(existing_room.get("name") or normalized_name)}
        created = False
    else:
        next_room_id = max((_as_int(room.get("id"), 0) for room in rooms if isinstance(room, dict)), default=0) + 1
        if next_room_id <= 0:
            next_room_id = (_stable_int(f"{home_id}:{normalized_name}") % 9_000_000) + 1_000_000
        room_payload = {"id": next_room_id, "name": normalized_name}
        rooms.append(room_payload)
        created = True

    if home_id > 0:
        existing_home_id = _get_value(home, "id", "home_id", "rrHomeId", "rr_home_id")
        if existing_home_id is None:
            home["id"] = home_id
    home["rooms"] = rooms
    inventory["home"] = home
    inventory["rooms"] = rooms
    _write_inventory(ctx, inventory)
    return room_payload, created


def _scene_param_payload(scene_request: dict[str, Any]) -> dict[str, Any]:
    if isinstance(scene_request, dict) and isinstance(scene_request.get("action"), dict):
        return scene_request
    param_value = _get_value(scene_request, "param", default={})
    if isinstance(param_value, dict):
        return param_value
    if isinstance(param_value, str) and param_value.strip():
        try:
            parsed = json.loads(param_value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _scene_param_string(scene_request: dict[str, Any]) -> str:
    if isinstance(scene_request, dict) and isinstance(scene_request.get("action"), dict):
        return _scene_param_json_string(scene_request)
    param_value = _get_value(scene_request, "param", default={})
    if isinstance(param_value, str):
        return param_value
    if param_value is None:
        return "{}"
    return json.dumps(param_value, ensure_ascii=False, separators=(",", ":"))


def _scene_device_id(scene_request: dict[str, Any], inventory: dict[str, Any], ctx: ServerContext) -> str:
    explicit_device_id = str(_get_value(scene_request, "deviceId", "device_id", default="")).strip()
    if explicit_device_id:
        return explicit_device_id

    param_payload = _scene_param_payload(scene_request)
    action_payload = param_payload.get("action")
    items = action_payload.get("items") if isinstance(action_payload, dict) else []
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            entity_id = str(_get_value(item, "entityId", "entity_id", default="")).strip()
            if entity_id:
                return entity_id

    for collection_key in ("devices", "received_devices", "receivedDevices"):
        devices_value = inventory.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        for device in devices:
            if not isinstance(device, dict):
                continue
            candidate = str(_get_value(device, "duid", "did", "device_id", "deviceId", default="")).strip()
            if candidate:
                return candidate
    return ctx.duid


def _scene_device_name(inventory: dict[str, Any], device_id: str) -> str:
    normalized_device_id = str(device_id).strip()
    for collection_key in ("devices", "received_devices", "receivedDevices"):
        devices_value = inventory.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        for device in devices:
            if not isinstance(device, dict):
                continue
            candidate = str(_get_value(device, "duid", "did", "device_id", "deviceId", default="")).strip()
            if candidate != normalized_device_id:
                continue
            name = str(_get_value(device, "name", "device_name", default="")).strip()
            if name:
                return name
    return ""


def _plugin_proxy_url(ctx: ServerContext, source_url: str) -> str:
    source = str(source_url or "").strip()
    if not source:
        return source
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
    encoded_source = quote(source, safe="")
    return f"https://{ctx.api_host}/plugin/proxy/{digest}.zip?src={encoded_source}"


def _proxied_plugin_records(
    ctx: ServerContext,
    records: Sequence[dict[str, Any]],
    *,
    url_key: str = "url",
) -> list[dict[str, Any]]:
    proxied: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        item = dict(record)
        source_url = str(item.get(url_key) or "").strip()
        if source_url:
            item[url_key] = _plugin_proxy_url(ctx, source_url)
        proxied.append(item)
    return proxied


def _create_inventory_scene(ctx: ServerContext, scene_request: dict[str, Any]) -> dict[str, Any]:
    inventory = _load_inventory(ctx)
    if not isinstance(inventory, dict):
        inventory = {}

    scenes_source = inventory.get("scenes")
    scenes = [dict(scene) for scene in scenes_source if isinstance(scene, dict)] if isinstance(scenes_source, list) else []

    home_id = _as_int(_get_value(scene_request, "homeId", default=_default_home_id(ctx)), _default_home_id(ctx))
    scene_name = str(_get_value(scene_request, "name", default=f"Routine {len(scenes) + 1}")).strip() or f"Routine {len(scenes) + 1}"
    scene_id = max((_as_int(_get_value(scene, "id", default=0), 0) for scene in scenes), default=0) + 1
    if scene_id <= 0:
        scene_id = (_stable_int(f"{home_id}:{scene_name}") % 9_000_000) + 1_000_000

    param_payload = _scene_param_payload(scene_request)
    param_payload, _ = _hydrate_scene_param_with_zone_ranges(ctx, param_payload)
    device_id = _scene_device_id(scene_request, inventory, ctx)
    device_name = _scene_device_name(inventory, device_id)
    tag_id = _get_value(scene_request, "tagId", default=_get_value(param_payload, "tagId"))

    scene_record: dict[str, Any] = {
        "id": scene_id,
        "name": scene_name,
        "param": _scene_param_json_string(param_payload),
        "enabled": _as_bool(_get_value(scene_request, "enabled", default=True), True),
        "extra": scene_request.get("extra") if isinstance(scene_request, dict) and "extra" in scene_request else None,
        "type": str(_get_value(scene_request, "type", default="WORKFLOW")),
        "device_id": device_id,
        "device_name": device_name,
    }
    if tag_id is not None:
        scene_record["tagId"] = str(tag_id)

    scenes.append(scene_record)
    inventory["scenes"] = scenes

    scene_order_value = inventory.get("scene_order")
    if isinstance(scene_order_value, list):
        scene_order = [_as_int(value, 0) for value in scene_order_value if _as_int(value, 0) > 0]
    else:
        scene_order = [_as_int(_get_value(scene, "id", default=0), 0) for scene in scenes[:-1] if _as_int(_get_value(scene, "id", default=0), 0) > 0]
    scene_order.append(scene_id)
    inventory["scene_order"] = scene_order

    home_scenes_value = inventory.get("home_scenes")
    home_scenes = [dict(scene) for scene in home_scenes_value if isinstance(scene, dict)] if isinstance(home_scenes_value, list) else []
    home_scenes.append(_build_scene_payload(scene_record, home_id=home_id, include_device_context=True))
    inventory["home_scenes"] = home_scenes

    home_value = inventory.get("home")
    home = dict(home_value) if isinstance(home_value, dict) else {}
    if _get_value(home, "id", "home_id", "rrHomeId", "rr_home_id") is None and home_id > 0:
        home["id"] = home_id
    inventory["home"] = home
    _write_inventory(ctx, inventory)
    return scene_record


def _normalize_devices(
    ctx: ServerContext,
    devices_raw: list[dict[str, Any]],
    *,
    now_ts: int,
    default_name_prefix: str = "Vacuum",
    runtime_connected_ids: set[str] | None = None,
    runtime_online_authoritative: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    connected_ids = runtime_connected_ids or set()
    products_by_id: dict[str, dict[str, Any]] = {}
    devices: list[dict[str, Any]] = []
    for index, raw in enumerate(devices_raw):
        raw_item = raw if isinstance(raw, dict) else {}
        fallback_duid = ctx.duid if index == 0 else f"{ctx.duid}_{index + 1}"
        duid = str(_get_value(raw_item, "duid", "did", "device_id", default=fallback_duid))
        local_key = ctx.resolve_device_localkey(
            did=str(_get_value(raw_item, "did", "device_did", default="")),
            duid=duid,
            model=str(_get_value(raw_item, "model", default="")),
            name=str(_get_value(raw_item, "name", "device_name", default="")),
            product_id=str(_get_value(raw_item, "product_id", "productId", default="")),
            source="web_home_data",
            assign_if_missing=True,
        )
        product_id = str(_get_value(raw_item, "product_id", "productId", default=f"product_{index + 1}"))
        model = str(_get_value(raw_item, "model", default="roborock.vacuum.a117"))
        category = str(_get_value(raw_item, "category", default="robot.vacuum.cleaner"))
        product_name = str(_get_value(raw_item, "product_name", "productName", default=_default_product_name(model)))
        timezone = str(_get_value(raw_item, "timezone", "timeZoneId", "time_zone_id", default=_DEFAULT_TIMEZONE))
        room_id_value = _get_value(raw_item, "room_id", "roomId")
        room_id = _as_int(room_id_value, 0) if room_id_value is not None else None
        runtime_online = _runtime_online_for_device(
            raw_item,
            runtime_connected_ids=connected_ids,
        )
        inventory_online = _as_bool(_get_value(raw_item, "online", default=True), True)
        resolved_online = runtime_online if runtime_online_authoritative else (inventory_online or runtime_online)
        device = {
            "duid": duid,
            "name": str(_get_value(raw_item, "name", "device_name", default=f"{default_name_prefix} {index + 1}")),
            "localKey": local_key,
            "productId": product_id,
            "fv": str(_get_value(raw_item, "fv", "firmware", "firmware_version", default="02.33.88")),
            "pv": str(_get_value(raw_item, "pv", "protocol_version", default="1.0")),
            "activeTime": _as_int(_get_value(raw_item, "active_time", "activeTime", default=now_ts), now_ts),
            "timeZoneId": timezone,
            "online": resolved_online,
            "sn": str(
                _get_value(
                    raw_item,
                    "sn",
                    "serial_number",
                    default=f"RR{hashlib.sha256(duid.encode()).hexdigest()[:12].upper()}",
                )
            ),
        }
        if room_id is not None and room_id > 0:
            device["roomId"] = room_id
        feature_set = _get_value(raw_item, "feature_set", "featureSet")
        if feature_set is not None:
            device["featureSet"] = str(feature_set)
        new_feature_set = _get_value(raw_item, "new_feature_set", "newFeatureSet")
        if new_feature_set is not None:
            device["newFeatureSet"] = str(new_feature_set)
        devices.append(device)
        if product_id not in products_by_id:
            product = {
                "id": product_id,
                "name": product_name,
                "model": model,
                "category": category,
                "code": str(_get_value(raw_item, "code", default=model.split(".")[-1] if model else "a117")),
                "iconUrl": str(_get_value(raw_item, "icon_url", "iconUrl", default="")),
            }
            capability = _get_value(raw_item, "capability")
            if capability is not None:
                product["capability"] = capability
            schema = _get_value(raw_item, "schema")
            if isinstance(schema, list):
                product["schema"] = schema
            products_by_id[product_id] = product
    return devices, list(products_by_id.values())


def _normalize_rooms(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    home_data = inventory.get("home")
    home = home_data if isinstance(home_data, dict) else {}
    rooms_value = _get_value(home, "rooms")
    if rooms_value is None:
        rooms_value = inventory.get("rooms")
    rooms_list = rooms_value if isinstance(rooms_value, list) else []
    rooms: list[dict[str, Any]] = []
    for index, room in enumerate(rooms_list):
        room_data = room if isinstance(room, dict) else {}
        room_id = _as_int(_get_value(room_data, "id", "room_id", default=index + 1), index + 1)
        room_name = str(_get_value(room_data, "name", default=f"Room {index + 1}"))
        rooms.append({"id": room_id, "name": room_name})
    if rooms:
        return rooms
    return [{"id": 1, "name": "Living Room"}]


def _build_web_state(ctx: ServerContext) -> dict[str, Any]:
    inventory = _load_inventory(ctx)
    home_value = inventory.get("home")
    home_data = home_value if isinstance(home_value, dict) else {}
    now_ts = int(time.time())
    runtime_connected_ids, any_runtime_connected = _runtime_connected_identity_set(ctx)
    raw_devices = inventory.get("devices")
    devices_source = raw_devices if isinstance(raw_devices, list) and raw_devices else [{}]
    devices, products = _normalize_devices(
        ctx,
        devices_source,
        now_ts=now_ts,
        runtime_connected_ids=runtime_connected_ids,
        runtime_online_authoritative=any_runtime_connected,
    )
    raw_received = _get_value(inventory, "received_devices", "receivedDevices", default=[])
    received_source = raw_received if isinstance(raw_received, list) else []
    received_devices, received_products = _normalize_devices(
        ctx,
        received_source,
        now_ts=now_ts,
        default_name_prefix="Shared Vacuum",
        runtime_connected_ids=runtime_connected_ids,
        runtime_online_authoritative=any_runtime_connected,
    )
    for product in received_products:
        product_id = str(product["id"])
        if all(existing["id"] != product_id for existing in products):
            products.append(product)

    home_id = _as_int(
        _get_value(home_data, "rr_home_id", "rrHomeId", "home_id", "id", default=_default_home_id(ctx)),
        _default_home_id(ctx),
    )
    home_name = str(_get_value(home_data, "name", "home_name", default=_DEFAULT_HOME_NAME))
    rooms = _normalize_rooms(inventory)
    home_payload = {
        "id": home_id,
        "name": home_name,
        "products": products,
        "devices": devices,
        "receivedDevices": received_devices,
        "rooms": rooms,
    }
    lon = _get_value(home_data, "lon")
    if lon is not None:
        home_payload["lon"] = lon
    lat = _get_value(home_data, "lat")
    if lat is not None:
        home_payload["lat"] = lat
    geo_name = _get_value(home_data, "geo_name", "geoName")
    if geo_name is not None:
        home_payload["geoName"] = geo_name

    scenes_value = inventory.get("scenes")
    scenes = scenes_value if isinstance(scenes_value, list) else []
    scene_order_value = inventory.get("scene_order")
    scene_order = scene_order_value if isinstance(scene_order_value, list) else []
    schedules_value = inventory.get("schedules")
    schedules = schedules_value if isinstance(schedules_value, dict) else {}
    return {
        "home_id": home_id,
        "home_name": home_name,
        "home_data": home_payload,
        "scenes": scenes,
        "scene_order": scene_order,
        "schedules": schedules,
    }


def _device_has_runtime_did(ctx: ServerContext, duid: str) -> bool:
    runtime_credentials = getattr(ctx, "runtime_credentials", None)
    if runtime_credentials is None:
        return False
    try:
        credential_device = runtime_credentials.resolve_device(duid=duid)
    except Exception:
        return False
    if credential_device is None:
        return False
    did = str(credential_device.get("did") or "").strip()
    mqtt_user = str(credential_device.get("device_mqtt_usr") or "").strip()
    return bool(did or mqtt_user)


def _filter_home_data_to_runtime_devices(ctx: ServerContext, home_data: dict[str, Any]) -> dict[str, Any]:
    filtered_home = dict(home_data)
    allowed_product_ids: set[str] = set()

    for collection_key in ("devices", "receivedDevices", "received_devices"):
        devices_value = home_data.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        filtered_devices: list[dict[str, Any]] = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            duid = str(_get_value(device, "duid", "did", default="")).strip()
            if not duid or not _device_has_runtime_did(ctx, duid):
                continue
            filtered_devices.append(dict(device))
            product_id = str(_get_value(device, "productId", "product_id", default="")).strip()
            if product_id:
                allowed_product_ids.add(product_id)
        filtered_home[collection_key] = filtered_devices

    products_value = home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    filtered_products: list[dict[str, Any]] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        product_id = str(_get_value(product, "id", "productId", "product_id", default="")).strip()
        if not product_id or product_id not in allowed_product_ids:
            continue
        filtered_products.append(dict(product))
    filtered_home["products"] = filtered_products
    return filtered_home


def _build_product_response(ctx: ServerContext, home_data: dict[str, Any]) -> dict[str, Any]:
    filtered_home_data = _filter_home_data_to_runtime_devices(ctx, home_data)
    products_value = filtered_home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    categories: dict[str, dict[str, Any]] = {}
    for product in products:
        if not isinstance(product, dict):
            continue
        raw_product_id = str(product.get("id") or "")
        category_name = str(product.get("category") or "robot.vacuum.cleaner")
        if category_name not in categories:
            category_id = len(categories) + 1
            categories[category_name] = {
                "category": {
                    "id": category_id,
                    "displayName": category_name,
                    "iconUrl": "",
                },
                "productList": [],
            }
        model = str(product.get("model") or "roborock.vacuum.a117")
        model_key = model.strip().lower()
        product_id = _MODEL_PRODUCT_ID_OVERRIDES.get(
            model_key,
            _as_int(raw_product_id, _stable_int(raw_product_id or category_name) % 1_000_000),
        )
        product_entry = {
            "id": product_id,
            "name": str(product.get("name") or _default_product_name(model)),
            "model": model,
            "packagename": f"com.roborock.{model.split('.')[-1]}",
            "ncMode": "global",
            "status": 10,
        }
        icon_url = product.get("iconUrl")
        if isinstance(icon_url, str) and icon_url:
            product_entry["picurl"] = icon_url
            product_entry["cardPicUrl"] = icon_url
            product_entry["pluginPicUrl"] = icon_url
        categories[category_name]["productList"].append(product_entry)
    return {"categoryDetailList": list(categories.values())}


def _build_get_url_by_email(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    region_upper = ctx.region.upper()
    return _ok(
        {
            "url": f"https://{ctx.api_host}",
            "countrycode": _default_country_code_for_region(region_upper),
            "country": region_upper,
        }
    )


def _build_get_home_detail(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    web_state = _build_web_state(ctx)
    home_id = web_state["home_id"]
    home_name = web_state["home_name"]
    filtered_home = _filter_home_data_to_runtime_devices(ctx, web_state["home_data"])
    devices_value = filtered_home.get("devices")
    devices = devices_value if isinstance(devices_value, list) else []
    device_order = [
        str(_get_value(device, "duid", "did", default="")).strip()
        for device in devices
        if isinstance(device, dict) and str(_get_value(device, "duid", "did", default="")).strip()
    ]
    return _ok(
        {
            # Keep cloud-compatible keys so the mobile app resolves home context
            # without falling back to stale cached data.
            "id": home_id,
            "name": home_name,
            "deviceListOrder": device_order,
            "rrHomeId": home_id,
            "rrHomeName": home_name,
            "tuyaHomeId": 0,
            "homeId": home_id,
        }
    )


def _build_user_info(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    cloud_user_data = _load_cloud_user_data(ctx) or {}
    snapshot = _load_cloud_full_snapshot(ctx) or {}
    meta_value = snapshot.get("meta")
    meta = meta_value if isinstance(meta_value, dict) else {}
    username = str(meta.get("username") or "").strip()

    email = str(_get_value(cloud_user_data, "email", default="") or "").strip()
    mobile = str(_get_value(cloud_user_data, "mobile", default="") or "").strip()
    if not email and "@" in username:
        email = username
    if not mobile and username.isdigit():
        mobile = username

    region_upper = ctx.region.upper()
    country = str(_get_value(cloud_user_data, "country", default=region_upper) or region_upper)
    countrycode = str(
        _get_value(
            cloud_user_data,
            "countrycode",
            default=_default_country_code_for_region(region_upper),
        )
        or _default_country_code_for_region(region_upper)
    )
    nickname = str(_get_value(cloud_user_data, "nickname", default="Local User") or "Local User")
    avatarurl = str(_get_value(cloud_user_data, "avatarurl", "avatarUrl", default=_DEFAULT_AVATAR_URL) or "")
    if not avatarurl:
        avatarurl = _DEFAULT_AVATAR_URL

    return _ok(
        {
            "email": email,
            "mobile": mobile,
            "countrycode": countrycode,
            "country": country,
            "nickname": nickname,
            "hasPassword": _as_bool(_get_value(cloud_user_data, "hasPassword", default=True), True),
            "avatarurl": avatarurl,
        }
    )


def _build_app_config(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params
    payload = dict(_APP_CONFIG_COMMON_DATA)
    if clean_path.rstrip("/") == "/api/v2/appconfig":
        payload.update(_APP_CONFIG_V2_EXTRAS)
    return _ok(payload)


def _build_app_feature_plugin(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    return _ok({"plugins": _proxied_plugin_records(ctx, _APP_FEATURE_PLUGIN_LIST)})


def _build_home_devices_order(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    web_state = _build_web_state(ctx)
    filtered_home = _filter_home_data_to_runtime_devices(ctx, web_state["home_data"])
    devices_value = filtered_home.get("devices")
    devices = devices_value if isinstance(devices_value, list) else []
    device_order = [
        str(_get_value(device, "duid", "did", default="")).strip()
        for device in devices
        if isinstance(device, dict) and str(_get_value(device, "duid", "did", default="")).strip()
    ]
    return _ok(device_order)


def _build_user_roles(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok([])


def _build_logout(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return _ok(True)


def _build_get_home_data(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    home_data = _enrich_home_data_with_cloud_snapshot(ctx, _build_web_state(ctx)["home_data"])
    home_data = _filter_home_data_to_runtime_devices(ctx, home_data)
    return wrap_response(home_data)


def _build_get_home_rooms(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    rooms = _build_web_state(ctx)["home_data"]["rooms"]
    return wrap_response(rooms)


def _build_post_home_rooms(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params
    room_name = _first_non_empty((body_params.get("name") or []) + (body_params.get("roomName") or []))
    home_id = _extract_home_id_from_rooms_path(ctx, clean_path)
    room_payload, created = _upsert_inventory_room(ctx, home_id=home_id, room_name=room_name)
    response_payload = {
        "id": room_payload["id"],
        "roomId": room_payload["id"],
        "name": room_payload["name"],
        "roomName": room_payload["name"],
        "homeId": home_id,
        "created": created,
    }
    return wrap_response(response_payload)


def _build_post_scene_create(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, clean_path
    scene_request = _scene_request_from_body(body_params)
    created_scene = _create_inventory_scene(ctx, scene_request)
    home_id = _as_int(_get_value(scene_request, "homeId", default=_default_home_id(ctx)), _default_home_id(ctx))
    return wrap_response(_build_scene_payload(created_scene, home_id=home_id, include_device_context=True))


def _device_records(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    out: list[dict[str, Any]] = []
    for key in ("devices", "receivedDevices", "received_devices"):
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        out.extend(item for item in value if isinstance(item, dict))
    return out


def _product_records(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    value = payload.get("products")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _find_device_record(payloads: Sequence[dict[str, Any] | None], device_id: str) -> dict[str, Any]:
    normalized_device_id = str(device_id or "").strip()
    if not normalized_device_id:
        return {}
    for payload in payloads:
        for item in _device_records(payload):
            candidate = str(_get_value(item, "duid", "did", "device_id", "deviceId", default="")).strip()
            if candidate == normalized_device_id:
                return dict(item)
    return {}


def _find_product_record(payloads: Sequence[dict[str, Any] | None], product_id: str) -> dict[str, Any]:
    normalized_product_id = str(product_id or "").strip()
    if not normalized_product_id:
        return {}
    for payload in payloads:
        for item in _product_records(payload):
            candidate = str(_get_value(item, "id", "productId", "product_id", default="")).strip()
            if candidate == normalized_product_id:
                return dict(item)
    return {}


def _enrich_home_data_with_cloud_snapshot(ctx: ServerContext, home_data: dict[str, Any]) -> dict[str, Any]:
    cloud_home_data = _load_cloud_home_data(ctx) or {}
    if not cloud_home_data:
        return home_data

    enriched_home = dict(home_data)

    products_value = home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    enriched_products: list[dict[str, Any]] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        merged_product = dict(product)
        product_id = str(_get_value(product, "id", "productId", "product_id", default="")).strip()
        raw_product = _find_product_record((cloud_home_data,), product_id)
        if raw_product:
            icon_url = _get_value(raw_product, "iconUrl", "icon_url")
            if icon_url is not None:
                merged_product["iconUrl"] = str(icon_url)
            capability = _get_value(raw_product, "capability")
            if capability is not None:
                merged_product["capability"] = capability
            schema = _get_value(raw_product, "schema")
            if isinstance(schema, list):
                merged_product["schema"] = schema
        enriched_products.append(merged_product)
    if enriched_products:
        enriched_home["products"] = enriched_products

    rooms_value = home_data.get("rooms")
    rooms = rooms_value if isinstance(rooms_value, list) else []
    room_name_by_id = {
        _as_int(room.get("id"), 0): str(room.get("name") or "")
        for room in rooms
        if isinstance(room, dict)
    }

    for collection_key in ("devices", "receivedDevices"):
        devices_value = home_data.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        enriched_devices: list[dict[str, Any]] = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            merged_device = dict(device)
            device_id = str(_get_value(device, "duid", "did", "device_id", "deviceId", default="")).strip()
            raw_device = _find_device_record((cloud_home_data,), device_id)
            if raw_device:
                for source_keys, target_key in (
                    (("iconUrl", "icon_url"), "iconUrl"),
                    (("share",), "share"),
                    (("tuyaMigrated",), "tuyaMigrated"),
                    (("extra",), "extra"),
                    (("featureSet", "feature_set"), "featureSet"),
                    (("newFeatureSet", "new_feature_set"), "newFeatureSet"),
                    (("deviceStatus",), "deviceStatus"),
                    (("silentOtaSwitch",), "silentOtaSwitch"),
                    (("f",), "f"),
                    (("createTime", "create_time"), "createTime"),
                    (("cid",), "cid"),
                ):
                    value = _get_value(raw_device, *source_keys)
                    if value is None or value == "":
                        continue
                    merged_device[target_key] = value
                room_id_value = _get_value(raw_device, "roomId", "room_id")
                if room_id_value is not None:
                    room_id = _as_int(room_id_value, 0)
                    if room_id > 0:
                        merged_device["roomId"] = room_id
                        room_name = room_name_by_id.get(room_id, "")
                        if room_name:
                            merged_device["roomName"] = room_name
            enriched_devices.append(merged_device)
        if enriched_devices:
            enriched_home[collection_key] = enriched_devices

    return enriched_home


def _split_param_values(values: Sequence[str]) -> list[str]:
    split_values: list[str] = []
    for value in values:
        for part in str(value or "").split(","):
            candidate = part.strip()
            if candidate:
                split_values.append(candidate)
    return split_values


def _build_scene_payload(
    scene: dict[str, Any],
    *,
    home_id: int | None,
    include_device_context: bool,
) -> dict[str, Any]:
    scene_id = _as_int(_get_value(scene, "id", default=0), 0)
    payload: dict[str, Any] = {
        "id": scene_id,
        "name": str(_get_value(scene, "name", default=f"Routine {scene_id}" if scene_id else "Routine")),
        "enabled": _as_bool(_get_value(scene, "enabled", default=True), True),
        "type": str(_get_value(scene, "type", default="WORKFLOW")),
    }
    if home_id is not None:
        payload["homeId"] = home_id
    if include_device_context:
        scene_device = str(_get_value(scene, "device_id", "deviceId", "duid", default="")).strip()
        if scene_device:
            payload["deviceId"] = scene_device
        scene_device_name = str(_get_value(scene, "device_name", "deviceName", default="")).strip()
        if scene_device_name:
            payload["deviceName"] = scene_device_name
    param = _get_value(scene, "param")
    if param is not None or "param" in scene:
        payload["param"] = param
    extra = scene.get("extra") if "extra" in scene else _get_value(scene, "extra")
    if extra is not None or "extra" in scene:
        payload["extra"] = extra
    tag_id = _get_value(scene, "tagId", "tag_id")
    if tag_id is not None:
        payload["tagId"] = str(tag_id)
    return payload


def _build_device_detail_payload(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params
    parts = [part for part in clean_path.strip("/").split("/") if part]
    device_id = parts[-2] if len(parts) >= 2 else ""
    cloud_home_data = _load_cloud_home_data(ctx) or {}
    inventory = _load_inventory(ctx)
    web_state = _build_web_state(ctx)
    home_data = web_state["home_data"]

    normalized_devices: list[dict[str, Any]] = []
    for key in ("devices", "receivedDevices"):
        value = home_data.get(key)
        if isinstance(value, list):
            normalized_devices.extend(item for item in value if isinstance(item, dict))
    normalized_device = next(
        (
            dict(item)
            for item in normalized_devices
            if str(_get_value(item, "duid", "did", default="")).strip() == device_id
        ),
        {},
    )
    raw_device = _find_device_record((cloud_home_data, inventory), device_id)

    product_id = str(
        _get_value(
            raw_device,
            "productId",
            "product_id",
            default=_get_value(normalized_device, "productId", "product_id", default=""),
        )
    ).strip()
    normalized_product = next(
        (
            dict(item)
            for item in (home_data.get("products") if isinstance(home_data.get("products"), list) else [])
            if str(_get_value(item, "id", default="")).strip() == product_id
        ),
        {},
    )
    raw_product = _find_product_record((cloud_home_data,), product_id)

    room_name_by_id = {
        _as_int(room.get("id"), 0): str(room.get("name") or "")
        for room in (home_data.get("rooms") if isinstance(home_data.get("rooms"), list) else [])
        if isinstance(room, dict)
    }
    room_id_value = _get_value(
        raw_device,
        "roomId",
        "room_id",
        default=_get_value(normalized_device, "roomId", "room_id", default=None),
    )
    room_id = _as_int(room_id_value, 0) if room_id_value is not None else 0

    product_payload: dict[str, Any] = {}
    if product_id:
        product_payload = {
            "id": product_id,
            "name": str(_get_value(raw_product, "name", default=_get_value(normalized_product, "name", default=""))),
            "model": str(
                _get_value(raw_product, "model", default=_get_value(normalized_product, "model", default=""))
            ),
            "category": str(
                _get_value(raw_product, "category", default=_get_value(normalized_product, "category", default=""))
            ),
        }
        capability = _get_value(raw_product, "capability", default=_get_value(normalized_product, "capability"))
        if capability is not None:
            product_payload["capability"] = capability
        schema = _get_value(raw_product, "schema", default=_get_value(normalized_product, "schema"))
        if isinstance(schema, list):
            product_payload["schema"] = schema

    payload: dict[str, Any] = {
        "duid": str(
            _get_value(raw_device, "duid", "did", "device_id", "deviceId", default=device_id or ctx.duid)
        ).strip(),
        "name": str(
            _get_value(raw_device, "name", "device_name", default=_get_value(normalized_device, "name", default=""))
        ),
        "attribute": _get_value(raw_device, "attribute", default=None),
        "localKey": str(
            _get_value(
                raw_device,
                "localKey",
                "local_key",
                "localkey",
                default=_get_value(normalized_device, "localKey", default=ctx.localkey),
            )
        ),
        "productId": product_id,
        "fv": str(_get_value(raw_device, "fv", default=_get_value(normalized_device, "fv", default=""))),
        "pv": str(_get_value(raw_device, "pv", default=_get_value(normalized_device, "pv", default=""))),
        "activeTime": _as_int(
            _get_value(
                raw_device,
                "activeTime",
                "active_time",
                default=_get_value(normalized_device, "activeTime", default=0),
            ),
            0,
        ),
        "runtimeEnv": _get_value(raw_device, "runtimeEnv", "runtime_env", default=None),
        "timeZoneId": str(
            _get_value(
                raw_device,
                "timeZoneId",
                "time_zone_id",
                "timezone",
                default=_get_value(normalized_device, "timeZoneId", default=_DEFAULT_TIMEZONE),
            )
        ),
        "iconUrl": str(_get_value(raw_device, "iconUrl", "icon_url", default="")),
        "lon": _get_value(raw_device, "lon", default=None),
        "lat": _get_value(raw_device, "lat", default=None),
        "online": _as_bool(
            _get_value(normalized_device, "online", default=_get_value(raw_device, "online", default=False)),
            False,
        ),
        "share": _as_bool(_get_value(raw_device, "share", default=False), False),
        "shareTime": _get_value(raw_device, "shareTime", "share_time", default=None),
        "tuyaMigrated": _as_bool(_get_value(raw_device, "tuyaMigrated", default=False), False),
        "extra": _get_value(raw_device, "extra", default="{}") or "{}",
        "sn": str(_get_value(raw_device, "sn", default=_get_value(normalized_device, "sn", default=""))),
        "deviceStatus": _get_value(raw_device, "deviceStatus", default={}) or {},
        "silentOtaSwitch": _as_bool(_get_value(raw_device, "silentOtaSwitch", default=False), False),
        "f": _as_bool(_get_value(raw_device, "f", default=False), False),
        "homeId": _as_int(_get_value(home_data, "id", default=0), 0),
        "homeName": str(_get_value(home_data, "name", default="")),
        "roomId": room_id_value,
        "tuyaUuid": _get_value(raw_device, "tuyaUuid", "tuya_uuid", default=None),
        "setting": _get_value(raw_device, "setting", default=None),
    }
    if room_id > 0:
        room_name = room_name_by_id.get(room_id, "")
        if room_name:
            payload["roomName"] = room_name
    feature_set = _get_value(
        raw_device,
        "featureSet",
        "feature_set",
        default=_get_value(normalized_device, "featureSet"),
    )
    if feature_set is not None:
        payload["featureSet"] = str(feature_set)
    new_feature_set = _get_value(
        raw_device,
        "newFeatureSet",
        "new_feature_set",
        default=_get_value(normalized_device, "newFeatureSet"),
    )
    if new_feature_set is not None:
        payload["newFeatureSet"] = str(new_feature_set)
    create_time = _get_value(raw_device, "createTime", "create_time")
    if create_time is not None:
        payload["createTime"] = _as_int(create_time, 0)
    payload["cid"] = _get_value(raw_device, "cid", default=None)
    payload["shareType"] = _get_value(raw_device, "shareType", "share_type", default=None)
    payload["shareExpiredTime"] = _get_value(raw_device, "shareExpiredTime", "share_expired_time", default=None)
    if product_payload:
        payload["product"] = product_payload
        payload["productName"] = str(product_payload.get("name") or "")
        payload["model"] = str(product_payload.get("model") or "")
        payload["category"] = str(product_payload.get("category") or "")
        if "capability" in product_payload:
            payload["capability"] = product_payload["capability"]
        if isinstance(product_payload.get("schema"), list):
            payload["schema"] = product_payload["schema"]
    return payload


def _build_get_device_extra(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    payload = _build_device_detail_payload(ctx, query_params, body_params, clean_path)
    return wrap_response(payload.get("extra", "{}") or "{}")


def _build_get_device(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    return wrap_response(_build_device_detail_payload(ctx, query_params, body_params, f"{clean_path.rstrip('/')}/extra"))


def _build_get_scenes(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params
    web_state = _build_web_state(ctx)
    scenes = web_state["scenes"]
    device_id = clean_path.rstrip("/").split("/")[-1]
    filtered: list[dict[str, Any]] = []
    for scene in scenes:
        if not isinstance(scene, dict):
            continue
        scene_device = _get_value(scene, "device_id", "deviceId", "duid")
        if scene_device and str(scene_device) != device_id:
            continue
        filtered.append(_build_scene_payload(scene, home_id=None, include_device_context=False))
    return wrap_response(filtered)


def _build_get_home_scenes(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params
    web_state = _build_web_state(ctx)
    requested_home_id = _as_int(clean_path.rstrip("/").split("/")[-1], 0)
    home_id = web_state["home_id"]
    if requested_home_id and requested_home_id != home_id:
        return wrap_response([])
    scenes = web_state["scenes"]
    payload = [
        _build_scene_payload(scene, home_id=home_id, include_device_context=True)
        for scene in scenes
        if isinstance(scene, dict)
    ]
    return wrap_response(payload)


def _build_get_scene_order(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = body_params, clean_path
    web_state = _build_web_state(ctx)
    requested_home_id = _as_int(_split_param_values(query_params.get("homeId", []))[0] if query_params.get("homeId") else 0, 0)
    home_id = web_state["home_id"]
    if requested_home_id and requested_home_id != home_id:
        return wrap_response([])
    allowed_device_ids = set(_split_param_values(query_params.get("duids", [])))
    scenes_by_id = {
        _as_int(_get_value(scene, "id", default=0), 0): scene
        for scene in web_state["scenes"]
        if isinstance(scene, dict) and _as_int(_get_value(scene, "id", default=0), 0) > 0
    }
    ordered_scene_ids: list[int] = []
    scene_order = web_state.get("scene_order")
    if isinstance(scene_order, list):
        for raw_scene_id in scene_order:
            scene_id = _as_int(raw_scene_id, 0)
            if scene_id <= 0 or scene_id in ordered_scene_ids:
                continue
            scene = scenes_by_id.get(scene_id)
            if not isinstance(scene, dict):
                continue
            scene_device = str(_get_value(scene, "device_id", "deviceId", "duid", default="")).strip()
            if allowed_device_ids and scene_device not in allowed_device_ids:
                continue
            ordered_scene_ids.append(scene_id)
    for scene in web_state["scenes"]:
        if not isinstance(scene, dict):
            continue
        scene_device = str(_get_value(scene, "device_id", "deviceId", "duid", default="")).strip()
        if allowed_device_ids and scene_device not in allowed_device_ids:
            continue
        scene_id = _as_int(_get_value(scene, "id", default=0), 0)
        if scene_id > 0 and scene_id not in ordered_scene_ids:
            ordered_scene_ids.append(scene_id)
    return wrap_response(ordered_scene_ids)


def _build_execute_scene(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params
    parts = [part for part in clean_path.strip("/").split("/") if part]
    scene_id = _as_int(parts[-2] if len(parts) >= 2 else 0, 0)
    web_state = _build_web_state(ctx)
    scene = next(
        (
            dict(candidate)
            for candidate in web_state["scenes"]
            if isinstance(candidate, dict) and _as_int(_get_value(candidate, "id", default=0), 0) == scene_id
        ),
        None,
    )
    if scene is None:
        raise RoutineExecutionError(f"Scene {scene_id} not found")
    scene = _hydrate_inventory_scene_ranges(ctx, scene)
    return wrap_response(_routine_runner_for_context(ctx).start_scene(scene))


def _build_put_scene_name(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params
    parts = [part for part in clean_path.strip("/").split("/") if part]
    scene_id = _as_int(parts[-2] if len(parts) >= 2 else 0, 0)
    scene_name = _first_non_empty(body_params.get("name") or [])
    if not scene_name:
        scene_request = _scene_request_from_body(body_params)
        scene_name = str(_get_value(scene_request, "name", default="")).strip()
    if not scene_name:
        raise RoutineExecutionError(f"Scene {scene_id} name is required")

    def apply_update(updated_scene: dict[str, Any], inventory: dict[str, Any]) -> None:
        _ = inventory
        updated_scene["name"] = scene_name

    updated_scene, home_id = _replace_inventory_scene(ctx, scene_id=scene_id, scene_updater=apply_update)
    return wrap_response(_build_scene_payload(updated_scene, home_id=home_id, include_device_context=True))


def _build_put_scene_param(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params
    parts = [part for part in clean_path.strip("/").split("/") if part]
    scene_id = _as_int(parts[-2] if len(parts) >= 2 else 0, 0)
    scene_request = _scene_request_from_body(body_params)
    param_payload = _scene_param_payload(scene_request)
    if not param_payload:
        raise RoutineExecutionError(f"Scene {scene_id} param payload is required")
    param_payload, _ = _hydrate_scene_param_with_zone_ranges(ctx, param_payload)

    def apply_update(updated_scene: dict[str, Any], inventory: dict[str, Any]) -> None:
        updated_scene["param"] = _scene_param_json_string(param_payload)
        device_id = _scene_device_id(scene_request, inventory, ctx)
        if device_id:
            updated_scene["device_id"] = device_id
            device_name = _scene_device_name(inventory, device_id)
            if device_name:
                updated_scene["device_name"] = device_name
        if "enabled" in scene_request:
            updated_scene["enabled"] = _as_bool(_get_value(scene_request, "enabled", default=True), True)
        if "type" in scene_request:
            updated_scene["type"] = str(_get_value(scene_request, "type", default="WORKFLOW"))
        if "extra" in scene_request:
            updated_scene["extra"] = scene_request.get("extra")
        tag_id = _get_value(scene_request, "tagId", default=_get_value(param_payload, "tagId"))
        if tag_id is not None:
            updated_scene["tagId"] = str(tag_id)

    updated_scene, home_id = _replace_inventory_scene(ctx, scene_id=scene_id, scene_updater=apply_update)
    return wrap_response(_build_scene_payload(updated_scene, home_id=home_id, include_device_context=True))


def _build_get_schedules(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params
    web_state = _build_web_state(ctx)
    parts = [part for part in clean_path.strip("/").split("/") if part]
    device_id = parts[-2] if len(parts) >= 2 else ""
    schedules_map = web_state["schedules"]
    schedules_raw = schedules_map.get(device_id) if isinstance(schedules_map, dict) else None
    if not isinstance(schedules_raw, list):
        schedules_raw = []
    schedules: list[dict[str, Any]] = []
    for index, schedule in enumerate(schedules_raw):
        raw = schedule if isinstance(schedule, dict) else {}
        schedules.append(
            {
                "id": _as_int(_get_value(raw, "id", default=index + 1), index + 1),
                "cron": str(_get_value(raw, "cron", default="0 0 * * *")),
                "repeated": _as_bool(_get_value(raw, "repeated", default=True), True),
                "enabled": _as_bool(_get_value(raw, "enabled", default=True), True),
                "param": _get_value(raw, "param", default={}) or {},
            }
        )
    return wrap_response(schedules)


def _build_post_app_info(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, clean_path
    payload = {"stored": True}
    for source_key, payload_key in (
        ("pushChannel", "pushChannel"),
        ("channelToken", "channelToken"),
        ("locale", "locale"),
        ("lang", "lang"),
        ("osType", "osType"),
    ):
        values = _split_param_values(body_params.get(source_key, []))
        if values:
            payload[payload_key] = values[0]
    return wrap_response(payload)


def _build_get_inbox_latest(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return wrap_response(
        {
            "count": 0,
            "hasUnread": False,
            "latest": None,
            "updatedAt": int(time.time()),
        }
    )


def _build_get_products(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    home_data = _build_web_state(ctx)["home_data"]
    return _ok(_build_product_response(ctx, home_data))


def _build_download_code(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    return _ok(_proxied_plugin_records(ctx, _APPPLUGIN_LIST))


def _build_download_category_code(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    return _ok({"categoryPluginList": _proxied_plugin_records(ctx, _CATEGORY_PLUGIN_LIST)})


def _build_add_device(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    home_data = _build_web_state(ctx)["home_data"]
    devices_value = home_data.get("devices")
    devices = devices_value if isinstance(devices_value, list) else []
    first_device = devices[0] if devices else {"duid": ctx.duid, "name": "Vacuum 1"}
    return wrap_response(
        {
            "duid": first_device.get("duid"),
            "name": first_device.get("name"),
        }
    )


@dataclass(frozen=True)
class EndpointRule:
    """Describes when a path matches and how to build its response."""

    name: str
    matcher: RouteMatcher
    build_response: RouteResponseFactory


def _match_region(path: str) -> bool:
    return path.rstrip("/") in ("", "/region", "/api/region", "/b/region", "/api/b/region")


def _match_nc_prepare(path: str) -> bool:
    return "nc" in path and ("prepare" in path or path.endswith("/nc"))


def _match_time(path: str) -> bool:
    return "time" in path


def _match_location(path: str) -> bool:
    return "location" in path


def _build_region(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = clean_path
    did = ctx.extract_did(query_params, body_params)
    host_override = _request_host_override(query_params)
    api_host = host_override or ctx.api_host
    mqtt_host = host_override or ctx.mqtt_host
    api_url = f"https://{api_host}"
    mqtt_url = f"ssl://{mqtt_host}:{ctx.mqtt_tls_port}"
    region_payload = {
        "apiUrl": api_url,
        "mqttUrl": mqtt_url,
        "api_url": api_url,
        "mqtt_url": mqtt_url,
    }
    # Keep encrypted bootstrap payload within a single RSA-OAEP block for firmware compatibility.
    if len(json.dumps(region_payload, ensure_ascii=True, separators=(",", ":"))) > _RSA_OAEP_SHA1_MAX_PLAINTEXT:
        region_payload = {"apiUrl": api_url, "mqttUrl": mqtt_url}
    encrypted = ctx.encrypt_bootstrap_result(did, region_payload)
    if encrypted is not None:
        return encrypted
    return wrap_response(region_payload)


def _build_nc_prepare(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = clean_path
    nc_data = ctx.nc_payload(query_params, body_params)
    did = str(nc_data.get("d") or ctx.extract_did(query_params, body_params))
    explicit_did = _extract_explicit_did(query_params, body_params)
    minimal_nc: dict[str, Any] = {
        "s": str(nc_data.get("s") or ""),
        "t": str(nc_data.get("t") or ""),
        "k": str(
            nc_data.get("k")
            or ctx.resolve_device_localkey(did=did, source="nc_prepare_minimal", assign_if_missing=False)
            or ctx.localkey
        ),
    }
    if did:
        minimal_nc["d"] = did
    encrypted = ctx.encrypt_bootstrap_result(explicit_did, minimal_nc) if explicit_did else None
    if encrypted is not None:
        return encrypted
    return wrap_response(minimal_nc)


def _build_time(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params, clean_path
    return wrap_response(int(time.time()))


def _build_location(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = query_params, body_params, clean_path
    return wrap_response({"country": ctx.region.upper(), "timezone": "America/New_York"})


def _build_catchall(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    _ = ctx, query_params, body_params
    return wrap_response({"ok": True, "route": clean_path})


def default_endpoint_rules() -> Sequence[EndpointRule]:
    """Returns endpoint rules in match priority order."""

    return (
        EndpointRule("get_url_by_email", _match_get_url_by_email, _build_get_url_by_email),
        EndpointRule("login_ml_c", _match_login_ml_c, _build_login_ml_c),
        EndpointRule("login_key_sign", _match_login_key_sign, _build_login_key_sign),
        EndpointRule("login_key_captcha", _match_login_key_captcha, _build_login_key_captcha),
        EndpointRule("login_email_code_send", _match_login_email_code_send, _build_login_email_code_send),
        EndpointRule("login_sms_code_send", _match_login_sms_code_send, _build_login_sms_code_send),
        EndpointRule("login_code_validate", _match_login_code_validate, _build_login_code_validate),
        EndpointRule("login_code_submit", _match_login_code_submit, _build_login_code_submit),
        EndpointRule("login_password_submit", _match_login_password_submit, _build_login_password_submit),
        EndpointRule("login_password_reset", _match_login_password_reset, _build_login_password_reset),
        EndpointRule("country_version", _match_country_version, _build_country_version),
        EndpointRule("country_list", _match_country_list, _build_country_list),
        EndpointRule("agreement_latest", _match_agreement_latest, _build_agreement_latest),
        EndpointRule("get_home_detail", _match_get_home_detail, _build_get_home_detail),
        EndpointRule("user_info", _match_user_info, _build_user_info),
        EndpointRule("app_config", _match_app_config, _build_app_config),
        EndpointRule("app_feature_plugin", _match_app_feature_plugin, _build_app_feature_plugin),
        EndpointRule("home_devices_order", _match_home_devices_order, _build_home_devices_order),
        EndpointRule("user_roles", _match_user_roles, _build_user_roles),
        EndpointRule("logout", _match_logout, _build_logout),
        EndpointRule("get_home_data", _match_get_home_data, _build_get_home_data),
        EndpointRule("post_home_rooms", _match_post_home_rooms, _build_post_home_rooms),
        EndpointRule("post_scene_create", _match_post_scene_create, _build_post_scene_create),
        EndpointRule("get_home_rooms", _match_get_home_rooms, _build_get_home_rooms),
        EndpointRule("get_scenes", _match_get_scenes, _build_get_scenes),
        EndpointRule("get_home_scenes", _match_get_home_scenes, _build_get_home_scenes),
        EndpointRule("get_scene_order", _match_get_scene_order, _build_get_scene_order),
        EndpointRule("put_scene_name", _match_put_scene_name, _build_put_scene_name),
        EndpointRule("put_scene_param", _match_put_scene_param, _build_put_scene_param),
        EndpointRule("execute_scene", _match_execute_scene, _build_execute_scene),
        EndpointRule("get_device", _match_get_device, _build_get_device),
        EndpointRule("get_device_extra", _match_get_device_extra, _build_get_device_extra),
        EndpointRule("get_schedules", _match_get_schedules, _build_get_schedules),
        EndpointRule("post_app_info", _match_post_app_info, _build_post_app_info),
        EndpointRule("get_inbox_latest", _match_get_inbox_latest, _build_get_inbox_latest),
        EndpointRule("get_products", _match_get_products, _build_get_products),
        EndpointRule("download_code", _match_download_code, _build_download_code),
        EndpointRule("download_category_code", _match_download_category_code, _build_download_category_code),
        EndpointRule("add_device", _match_add_device, _build_add_device),
        EndpointRule("region", _match_region, _build_region),
        EndpointRule("nc_prepare", _match_nc_prepare, _build_nc_prepare),
        EndpointRule("time", _match_time, _build_time),
        EndpointRule("location", _match_location, _build_location),
        EndpointRule("catchall", lambda _path: True, _build_catchall),
    )


def resolve_route(
    *,
    rules: Sequence[EndpointRule],
    context: ServerContext,
    clean_path: str,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    method: str = "GET",
) -> tuple[str, dict[str, Any]]:
    """Resolves the first matching rule and returns (rule_name, response_payload)."""

    for rule in rules:
        try:
            matched = rule.matcher(clean_path, method)
        except TypeError:
            matched = rule.matcher(clean_path)
        if matched:
            return rule.name, rule.build_response(context, query_params, body_params, clean_path)
    return "catchall", _build_catchall(context, query_params, body_params, clean_path)
