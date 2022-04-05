# -*- coding: utf-8 -*-

import base64
import traceback
from time import time

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from plone.memoize import ram

# jwks = {
# "keys":[{"kty":"RSA","use":"sig","kid":"nOo3ZDrODXEK1jKWhXslHR_KXEg","x5t":"nOo3ZDrODXEK1jKWhXslHR_KXEg","n":"oaLLT9hkcSj2tGfZsjbu7Xz1Krs0qEicXPmEsJKOBQHauZ_kRM1HdEkgOJbUznUspE6xOuOSXjlzErqBxXAu4SCvcvVOCYG2v9G3-uIrLF5dstD0sYHBo1VomtKxzF90Vslrkn6rNQgUGIWgvuQTxm1uRklYFPEcTIRw0LnYknzJ06GC9ljKR617wABVrZNkBuDgQKj37qcyxoaxIGdxEcmVFZXJyrxDgdXh9owRmZn6LIJlGjZ9m59emfuwnBnsIQG7DirJwe9SXrLXnexRQWqyzCdkYaOqkpKrsjuxUj2-MHX31FqsdpJJsOAvYXGOYBKJRjhGrGdONVrZdUdTBQ","e":"AQAB","x5c":["MIIDBTCCAe2gAwIBAgIQN33ROaIJ6bJBWDCxtmJEbjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIwMTIyMTIwNTAxN1oXDTI1MTIyMDIwNTAxN1owLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKGiy0/YZHEo9rRn2bI27u189Sq7NKhInFz5hLCSjgUB2rmf5ETNR3RJIDiW1M51LKROsTrjkl45cxK6gcVwLuEgr3L1TgmBtr/Rt/riKyxeXbLQ9LGBwaNVaJrSscxfdFbJa5J+qzUIFBiFoL7kE8ZtbkZJWBTxHEyEcNC52JJ8ydOhgvZYykete8AAVa2TZAbg4ECo9+6nMsaGsSBncRHJlRWVycq8Q4HV4faMEZmZ+iyCZRo2fZufXpn7sJwZ7CEBuw4qycHvUl6y153sUUFqsswnZGGjqpKSq7I7sVI9vjB199RarHaSSbDgL2FxjmASiUY4RqxnTjVa2XVHUwUCAwEAAaMhMB8wHQYDVR0OBBYEFI5mN5ftHloEDVNoIa8sQs7kJAeTMA0GCSqGSIb3DQEBCwUAA4IBAQBnaGnojxNgnV4+TCPZ9br4ox1nRn9tzY8b5pwKTW2McJTe0yEvrHyaItK8KbmeKJOBvASf+QwHkp+F2BAXzRiTl4Z+gNFQULPzsQWpmKlz6fIWhc7ksgpTkMK6AaTbwWYTfmpKnQw/KJm/6rboLDWYyKFpQcStu67RZ+aRvQz68Ev2ga5JsXlcOJ3gP/lE5WC1S0rjfabzdMOGP8qZQhXk4wBOgtFBaisDnbjV5pcIrjRPlhoCxvKgC/290nZ9/DLBH3TbHk8xwHXeBAnAjyAqOZij92uksAv7ZLq4MODcnQshVINXwsYshG1pQqOLwMertNaY5WtrubMRku44Dw7R"]},{"kty":"RSA","use":"sig","kid":"l3sQ-50cCH4xBVZLHTGwnSR7680","x5t":"l3sQ-50cCH4xBVZLHTGwnSR7680","n":"sfsXMXWuO-dniLaIELa3Pyqz9Y_rWff_AVrCAnFSdPHa8__Pmkbt_yq-6Z3u1o4gjRpKWnrjxIh8zDn1Z1RS26nkKcNg5xfWxR2K8CPbSbY8gMrp_4pZn7tgrEmoLMkwfgYaVC-4MiFEo1P2gd9mCdgIICaNeYkG1bIPTnaqquTM5KfT971MpuOVOdM1ysiejdcNDvEb7v284PYZkw2imwqiBY3FR0sVG7jgKUotFvhd7TR5WsA20GS_6ZIkUUlLUbG_rXWGl0YjZLS_Uf4q8Hbo7u-7MaFn8B69F6YaFdDlXm_A0SpedVFWQFGzMsp43_6vEzjfrFDJVAYkwb6xUQ","e":"AQAB","x5c":["MIIDBTCCAe2gAwIBAgIQWPB1ofOpA7FFlOBk5iPaNTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIxMDIwNzE3MDAzOVoXDTI2MDIwNjE3MDAzOVowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALH7FzF1rjvnZ4i2iBC2tz8qs/WP61n3/wFawgJxUnTx2vP/z5pG7f8qvumd7taOII0aSlp648SIfMw59WdUUtup5CnDYOcX1sUdivAj20m2PIDK6f+KWZ+7YKxJqCzJMH4GGlQvuDIhRKNT9oHfZgnYCCAmjXmJBtWyD052qqrkzOSn0/e9TKbjlTnTNcrIno3XDQ7xG+79vOD2GZMNopsKogWNxUdLFRu44ClKLRb4Xe00eVrANtBkv+mSJFFJS1Gxv611hpdGI2S0v1H+KvB26O7vuzGhZ/AevRemGhXQ5V5vwNEqXnVRVkBRszLKeN/+rxM436xQyVQGJMG+sVECAwEAAaMhMB8wHQYDVR0OBBYEFLlRBSxxgmNPObCFrl+hSsbcvRkcMA0GCSqGSIb3DQEBCwUAA4IBAQB+UQFTNs6BUY3AIGkS2ZRuZgJsNEr/ZEM4aCs2domd2Oqj7+5iWsnPh5CugFnI4nd+ZLgKVHSD6acQ27we+eNY6gxfpQCY1fiN/uKOOsA0If8IbPdBEhtPerRgPJFXLHaYVqD8UYDo5KNCcoB4Kh8nvCWRGPUUHPRqp7AnAcVrcbiXA/bmMCnFWuNNahcaAKiJTxYlKDaDIiPN35yECYbDj0PBWJUxobrvj5I275jbikkp8QSLYnSU/v7dMDUbxSLfZ7zsTuaF2Qx+L62PsYTwLzIFX3M8EMSQ6h68TupFTi5n0M2yIXQgoRoNEDWNJZ/aZMY/gqT02GQGBWrh+/vJ"]},{"kty":"RSA","use":"sig","kid":"Mr5-AUibfBii7Nd1jBebaxboXW0","x5t":"Mr5-AUibfBii7Nd1jBebaxboXW0","n":"yr3v1uETrFfT17zvOiy01w8nO-1t67cmiZLZxq2ISDdte9dw-IxCR7lPV2wezczIRgcWmYgFnsk2j6m10H4tKzcqZM0JJ_NigY29pFimxlL7_qXMB1PorFJdlAKvp5SgjSTwLrXjkr1AqWwbpzG2yZUNN3GE8GvmTeo4yweQbNCd-yO_Zpozx0J34wHBEMuaw-ZfCUk7mdKKsg-EcE4Zv0Xgl9wP2MpKPx0V8gLazxe6UQ9ShzNuruSOncpLYJN_oQ4aKf5ptOp1rsfDY2IK9frtmRTKOdQ-MEmSdjGL_88IQcvCs7jqVz53XKoXRlXB8tMIGOcg-ICer6yxe2itIQ","e":"AQAB","x5c":["MIIDBTCCAe2gAwIBAgIQff8yrFO3CINPHUTT76tUsTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIxMTAyNDE3NDU1NloXDTI2MTAyNDE3NDU1NlowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMq979bhE6xX09e87zostNcPJzvtbeu3JomS2catiEg3bXvXcPiMQke5T1dsHs3MyEYHFpmIBZ7JNo+ptdB+LSs3KmTNCSfzYoGNvaRYpsZS+/6lzAdT6KxSXZQCr6eUoI0k8C6145K9QKlsG6cxtsmVDTdxhPBr5k3qOMsHkGzQnfsjv2aaM8dCd+MBwRDLmsPmXwlJO5nSirIPhHBOGb9F4JfcD9jKSj8dFfIC2s8XulEPUoczbq7kjp3KS2CTf6EOGin+abTqda7Hw2NiCvX67ZkUyjnUPjBJknYxi//PCEHLwrO46lc+d1yqF0ZVwfLTCBjnIPiAnq+ssXtorSECAwEAAaMhMB8wHQYDVR0OBBYEFDiZG6s5d9RvorpqbVdS2/MD8ZKhMA0GCSqGSIb3DQEBCwUAA4IBAQAQAPuqqKj2AgfC9ayx+qUu0vjzKYdZ6T+3ssJDOGwB1cLMXMTUVgFwj8bsX1ahDUJdzKpWtNj7bno+Ug85IyU7k89U0Ygr55zWU5h4wnnRrCu9QKvudUPnbiXoVuHPwcK8w1fdXZQB5Qq/kKzhNGY57cG1bwj3R/aIdCp+BjgFppOKjJpK7FKS8G2v70eIiCLMapK9lLEeQOxIvzctTsXy9EZ7wtaIiYky4ZSituphToJUkakHaQ6evbn82lTg6WZz1tmSmYnPqRdAff7aiQ1Sw9HpuzlZY/piTVqvd6AfKZqyxu/FhENE0Odv/0hlHzI15jKQWL1Ljc0Nm3y1skut"]},{"kty":"RSA","use":"sig","kid":"jS1Xo1OWDj_52vbwGNgvQO2VzMc","x5t":"jS1Xo1OWDj_52vbwGNgvQO2VzMc","n":"spvQcXWqYrMcvcqQmfSMYnbUC8U03YctnXyLIBe148OzhBrgdAOmPfMfJi_tUW8L9svVGpk5qG6dN0n669cRHKqU52GnG0tlyYXmzFC1hzHVgQz9ehve4tlJ7uw936XIUOAOxx3X20zdpx7gm4zHx4j2ZBlXskAj6U3adpHQNuwUE6kmngJWR-deWlEigMpRsvUVQ2O5h0-RSq8Wr_x7ud3K6GTtrzARamz9uk2IXatKYdnj5Jrk2jLY6nWt-GtxlA_l9XwIrOl6Sqa_pOGIpS01JKdxKvpBC9VdS8oXB-7P5qLksmv7tq-SbbiOec0cvU7WP7vURv104V4FiI_qoQ","e":"AQAB","x5c":["MIIDBTCCAe2gAwIBAgIQHsetP+i8i6VIAmjmfVGv6jANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIyMDEzMDIzMDYxNFoXDTI3MDEzMDIzMDYxNFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALKb0HF1qmKzHL3KkJn0jGJ21AvFNN2HLZ18iyAXtePDs4Qa4HQDpj3zHyYv7VFvC/bL1RqZOahunTdJ+uvXERyqlOdhpxtLZcmF5sxQtYcx1YEM/Xob3uLZSe7sPd+lyFDgDscd19tM3ace4JuMx8eI9mQZV7JAI+lN2naR0DbsFBOpJp4CVkfnXlpRIoDKUbL1FUNjuYdPkUqvFq/8e7ndyuhk7a8wEWps/bpNiF2rSmHZ4+Sa5Noy2Op1rfhrcZQP5fV8CKzpekqmv6ThiKUtNSSncSr6QQvVXUvKFwfuz+ai5LJr+7avkm24jnnNHL1O1j+71Eb9dOFeBYiP6qECAwEAAaMhMB8wHQYDVR0OBBYEFGzVFjAbYpU/2en4ry4LMLUHJ3GjMA0GCSqGSIb3DQEBCwUAA4IBAQBU0YdNVfdByvpwsPfwNdD8m1PLeeCKmLHQnWRI5600yEHuoUvoAJd5dwe1ZU1bHHRRKWN7AktUzofP3yF61xtizhEbyPjHK1tnR+iPEviWxVvK37HtfEPzuh1Vqp08bqY15McYUtf77l2HXTpak+UWYRYJBi++2umIDKY5UMqU+LEZnvaXybLUKN3xG4iy2q1Ab8syGFaUP7J3nCtVrR7ip39BnvSTTZZNo/OC7fYXJ2X4sN1/2ZhR5EtnAgwi2RvlZl0aWPrczArUCxDBCbsKPL/Up/kID1ir1VO4LT09ryfv2nx3y6l0YvuL7ePz4nGYCWHcbMVcUrQUXquZ3XtI"]},{"kty":"RSA","use":"sig","kid":"DqUu8gf-nAgcyjP3-SuplNAXAnc","x5t":"DqUu8gf-nAgcyjP3-SuplNAXAnc","n":"1n7-nWSLeuWQzBRlYSbS8RjvWvkQeD7QL9fOWaGXbW73VNGH0YipZisPClFv6GzwfWECTWQp19WFe_lASka5-KEWkQVzCbEMaaafOIs7hC61P5cGgw7dhuW4s7f6ZYGZEzQ4F5rHE-YNRbvD51qirPNzKHk3nji1wrh0YtbPPIf--NbI98bCwLLh9avedOmqESzWOGECEMXv8LSM-B9SKg_4QuBtyBwwIakTuqo84swTBM5w8PdhpWZZDtPgH87Wz-_WjWvk99AjXl7l8pWPQJiKNujt_ck3NDFpzaLEppodhUsID0ptRA008eCU6l8T-ux19wZmb_yBnHcV3pFWhQ","e":"AQAB","x5c":["MIIC8TCCAdmgAwIBAgIQYVk/tJ1e4phISvVrAALNKTANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMjAxMjIxMDAwMDAwWhcNMjUxMjIxMDAwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWfv6dZIt65ZDMFGVhJtLxGO9a+RB4PtAv185ZoZdtbvdU0YfRiKlmKw8KUW/obPB9YQJNZCnX1YV7+UBKRrn4oRaRBXMJsQxppp84izuELrU/lwaDDt2G5bizt/plgZkTNDgXmscT5g1Fu8PnWqKs83MoeTeeOLXCuHRi1s88h/741sj3xsLAsuH1q9506aoRLNY4YQIQxe/wtIz4H1IqD/hC4G3IHDAhqRO6qjzizBMEznDw92GlZlkO0+AfztbP79aNa+T30CNeXuXylY9AmIo26O39yTc0MWnNosSmmh2FSwgPSm1EDTTx4JTqXxP67HX3BmZv/IGcdxXekVaFAgMBAAGjITAfMB0GA1UdDgQWBBQ2r//lgTPcKughDkzmCtRlw+P9SzANBgkqhkiG9w0BAQsFAAOCAQEAsFdRyczNWh/qpYvcIZbDvWYzlrmFZc6blcUzns9zf7sUWtQZrZPu5DbetV2Gr2r3qtMDKXCUaR+pqoy3I2zxTX3x8bTNhZD9YAgAFlTLNSydTaK5RHyB/5kr6B7ZJeNIk3PRVhRGt6ybCJSjV/VYVkLR5fdLP+5GhvBESobAR/d0ntriTzp7/tLMb/oXx7w5Hu1m3I8rpMocoXfH2SH1GLmMXj6Mx1dtwCDYM6bsb3fhWRz9O9OMR6QNiTnq8q9wn1QzBAnRcswYzT1LKKBPNFSasCvLYOCPOZCL+W8N8jqa9ZRYNYKWXzmiSptgBEM24t3m5FUWzWqoLu9pIcnkPQ=="]},{"kty":"RSA","use":"sig","kid":"OzZ5Dbmcso9Qzt2ModGmihg30Bo","x5t":"OzZ5Dbmcso9Qzt2ModGmihg30Bo","n":"01re9a2BUTtNtdFzLNI-QEHW8XhDiDMDbGMkxHRIYXH41zBccsXwH9vMi0HuxXHpXOzwtUYKwl93ZR37tp6lpvwlU1HePNmZpJ9D-XAvU73x03YKoZEdaFB39VsVyLih3fuPv6DPE2qT-TNE3X5YdIWOGFrcMkcXLsjO-BCq4qcSdBH2lBgEQUuD6nqreLZsg-gPzSDhjVScIUZGiD8M2sKxADiIHo5KlaZIyu32t8JkavP9jM7ItSAjzig1W2yvVQzUQZA-xZqJo2jxB3g_fygdPUHK6UN-_cqkrfxn2-VWH1wMhlm90SpxTMD4HoYOViz1ggH8GCX2aBiX5OzQ6Q","e":"AQAB","x5c":["MIIC8TCCAdmgAwIBAgIQQrXPXIlUE4JMTMkVj+02YTANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMjEwMzEwMDAwMDAwWhcNMjYwMzEwMDAwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTWt71rYFRO0210XMs0j5AQdbxeEOIMwNsYyTEdEhhcfjXMFxyxfAf28yLQe7Fcelc7PC1RgrCX3dlHfu2nqWm/CVTUd482Zmkn0P5cC9TvfHTdgqhkR1oUHf1WxXIuKHd+4+/oM8TapP5M0Tdflh0hY4YWtwyRxcuyM74EKripxJ0EfaUGARBS4Pqeqt4tmyD6A/NIOGNVJwhRkaIPwzawrEAOIgejkqVpkjK7fa3wmRq8/2Mzsi1ICPOKDVbbK9VDNRBkD7FmomjaPEHeD9/KB09QcrpQ379yqSt/Gfb5VYfXAyGWb3RKnFMwPgehg5WLPWCAfwYJfZoGJfk7NDpAgMBAAGjITAfMB0GA1UdDgQWBBTECjBRANDPLGrn1p7qtwswtBU7JzANBgkqhkiG9w0BAQsFAAOCAQEAq1Ib4ERvXG5kiVmhfLOpun2ElVOLY+XkvVlyVjq35rZmSIGxgfFc08QOQFVmrWQYrlss0LbboH0cIKiD6+rVoZTMWxGEicOcGNFzrkcG0ulu0cghKYID3GKDTftYKEPkvu2vQmueqa4t2tT3PlYF7Fi2dboR5Y96Ugs8zqNwdBMRm677N/tJBk53CsOf9NnBaxZ1EGArmEHHIb80vODStv35ueLrfMRtCF/HcgkGxy2U8kaCzYmmzHh4zYDkeCwM3Cq2bGkG+Efe9hFYfDHw13DzTR+h9pPqFFiAxnZ3ofT96NrZHdYjwbfmM8cw3ldg0xQzGcwZjtyYmwJ6sDdRvQ=="]}]}


def decode_jwt(user, data, valid_audiences, issuer, key_discovery_url):
    """
        Decodes JWT token and extracts user info.

        :param user:
            :class`authomatic.core.User``

            Interface to selected user info

        :param dict data:

            JWT Token data

        :param str valid_audiences:

            Tenant id

        :returns:
            dict of decoded user info

    """
    jwks = get_jwks(key_discovery_url)
    try:
        user_info = validate_jwt(data['id_token'], valid_audiences, issuer, jwks)
    except Exception as ex:
        traceback.print_exc()
        print('The JWT is not valid!')
    else:
        print('The JWT is valid')

    return user_info

@ram.cache(lambda *args: time() // (60 * 60 * 24))
def get_jwks(key_discovery_url):
    r = requests.get(key_discovery_url)
    if r.raise_for_status() is None:
        jwks= r.json()
    return jwks

def ensure_bytes(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key

def decode_value(val):
    decoded = base64.urlsafe_b64decode(ensure_bytes(val) + b'==')
    return int.from_bytes(decoded, 'big')

def rsa_pem_from_jwk(jwk):
    return RSAPublicNumbers(
        n=decode_value(jwk['n']),
        e=decode_value(jwk['e'])
    ).public_key(default_backend()).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)

def get_kid(token):
    headers = jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing header')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidAuthorizationToken('missing kid')

def get_jwk(kid, jwks):
    for jwk in jwks.get('keys'):
        if jwk.get('kid') == kid:
            return jwk
    raise InvalidAuthorizationToken('kid not recognised')

def get_public_key(token, jwks):
    return rsa_pem_from_jwk(get_jwk(get_kid(token), jwks))

def validate_jwt(jwt_to_validate, valid_audiences, issuer, jwks):
    public_key = get_public_key(jwt_to_validate, jwks)

    decoded = jwt.decode(jwt_to_validate,
                         public_key,
                         verify=True,
                         algorithms=['RS256'],
                         audience=valid_audiences,
                         issuer=issuer)

    return decoded
