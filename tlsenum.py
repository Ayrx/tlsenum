#!/usr/bin/env python3
import argparse
import socket

tls_mapping = {
    "TLS_NULL_WITH_NULL_NULL": "0x00:0x00",
    "TLS_RSA_WITH_NULL_MD5": "0x00:0x01",
    "TLS_RSA_WITH_NULL_SHA": "0x00:0x02",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5": "0x00:0x03",
    "TLS_RSA_WITH_RC4_128_MD5": "0x00:0x04",
    "TLS_RSA_WITH_RC4_128_SHA": "0x00:0x05",
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5": "0x00:0x06",
    "TLS_RSA_WITH_IDEA_CBC_SHA": "0x00:0x07",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA": "0x00:0x08",
    "TLS_RSA_WITH_DES_CBC_SHA": "0x00:0x09",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "0x00:0x0A",
    "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA": "0x00:0x0B",
    "TLS_DH_DSS_WITH_DES_CBC_SHA": "0x00:0x0C",
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA": "0x00:0x0D",
    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA": "0x00:0x0E",
    "TLS_DH_RSA_WITH_DES_CBC_SHA": "0x00:0x0F",
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA": "0x00:0x10",
    "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA": "0x00:0x11",
    "TLS_DHE_DSS_WITH_DES_CBC_SHA": "0x00:0x12",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA": "0x00:0x13",
    "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA": "0x00:0x14",
    "TLS_DHE_RSA_WITH_DES_CBC_SHA": "0x00:0x15",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA": "0x00:0x16",
    "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5": "0x00:0x17",
    "TLS_DH_anon_WITH_RC4_128_MD5": "0x00:0x18",
    "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA": "0x00:0x19",
    "TLS_DH_anon_WITH_DES_CBC_SHA": "0x00:0x1A",
    "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA": "0x00:0x1B",
    "TLS_KRB5_WITH_DES_CBC_SHA": "0x00:0x1E",
    "TLS_KRB5_WITH_3DES_EDE_CBC_SHA": "0x00:0x1F",
    "TLS_KRB5_WITH_RC4_128_SHA": "0x00:0x20",
    "TLS_KRB5_WITH_IDEA_CBC_SHA": "0x00:0x21",
    "TLS_KRB5_WITH_DES_CBC_MD5": "0x00:0x22",
    "TLS_KRB5_WITH_3DES_EDE_CBC_MD5": "0x00:0x23",
    "TLS_KRB5_WITH_RC4_128_MD5": "0x00:0x24",
    "TLS_KRB5_WITH_IDEA_CBC_MD5": "0x00:0x25",
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA": "0x00:0x26",
    "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA": "0x00:0x27",
    "TLS_KRB5_EXPORT_WITH_RC4_40_SHA": "0x00:0x28",
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5": "0x00:0x29",
    "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5": "0x00:0x2A",
    "TLS_KRB5_EXPORT_WITH_RC4_40_MD5": "0x00:0x2B",
    "TLS_PSK_WITH_NULL_SHA": "0x00:0x2C",
    "TLS_DHE_PSK_WITH_NULL_SHA": "0x00:0x2D",
    "TLS_RSA_PSK_WITH_NULL_SHA": "0x00:0x2E",
    "TLS_RSA_WITH_AES_128_CBC_SHA": "0x00:0x2F",
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA": "0x00:0x30",
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA": "0x00:0x31",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA": "0x00:0x32",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": "0x00:0x33",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA": "0x00:0x34",
    "TLS_RSA_WITH_AES_256_CBC_SHA": "0x00:0x35",
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA": "0x00:0x36",
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA": "0x00:0x37",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA": "0x00:0x38",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": "0x00:0x39",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA": "0x00:0x3A",
    "TLS_RSA_WITH_NULL_SHA256": "0x00:0x3B",
    "TLS_RSA_WITH_AES_128_CBC_SHA256": "0x00:0x3C",
    "TLS_RSA_WITH_AES_256_CBC_SHA256": "0x00:0x3D",
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256": "0x00:0x3E",
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA256": "0x00:0x3F",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256": "0x00:0x40",
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA": "0x00:0x41",
    "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA": "0x00:0x42",
    "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA": "0x00:0x43",
    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA": "0x00:0x44",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA": "0x00:0x45",
    "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA": "0x00:0x46",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": "0x00:0x67",
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256": "0x00:0x68",
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA256": "0x00:0x69",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": "0x00:0x6A",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": "0x00:0x6B",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA256": "0x00:0x6C",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA256": "0x00:0x6D",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA": "0x00:0x84",
    "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA": "0x00:0x85",
    "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA": "0x00:0x86",
    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA": "0x00:0x87",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA": "0x00:0x88",
    "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA": "0x00:0x89",
    "TLS_PSK_WITH_RC4_128_SHA": "0x00:0x8A",
    "TLS_PSK_WITH_3DES_EDE_CBC_SHA": "0x00:0x8B",
    "TLS_PSK_WITH_AES_128_CBC_SHA": "0x00:0x8C",
    "TLS_PSK_WITH_AES_256_CBC_SHA": "0x00:0x8D",
    "TLS_DHE_PSK_WITH_RC4_128_SHA": "0x00:0x8E",
    "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA": "0x00:0x8F",
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA": "0x00:0x90",
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA": "0x00:0x91",
    "TLS_RSA_PSK_WITH_RC4_128_SHA": "0x00:0x92",
    "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA": "0x00:0x93",
    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA": "0x00:0x94",
    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA": "0x00:0x95",
    "TLS_RSA_WITH_SEED_CBC_SHA": "0x00:0x96",
    "TLS_DH_DSS_WITH_SEED_CBC_SHA": "0x00:0x97",
    "TLS_DH_RSA_WITH_SEED_CBC_SHA": "0x00:0x98",
    "TLS_DHE_DSS_WITH_SEED_CBC_SHA": "0x00:0x99",
    "TLS_DHE_RSA_WITH_SEED_CBC_SHA": "0x00:0x9A",
    "TLS_DH_anon_WITH_SEED_CBC_SHA": "0x00:0x9B",
    "TLS_RSA_WITH_AES_128_GCM_SHA256": "0x00:0x9C",
    "TLS_RSA_WITH_AES_256_GCM_SHA384": "0x00:0x9D",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": "0x00:0x9E",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": "0x00:0x9F",
    "TLS_DH_RSA_WITH_AES_128_GCM_SHA256": "0x00:0xA0",
    "TLS_DH_RSA_WITH_AES_256_GCM_SHA384": "0x00:0xA1",
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256": "0x00:0xA2",
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384": "0x00:0xA3",
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256": "0x00:0xA4",
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384": "0x00:0xA5",
    "TLS_DH_anon_WITH_AES_128_GCM_SHA256": "0x00:0xA6",
    "TLS_DH_anon_WITH_AES_256_GCM_SHA384": "0x00:0xA7",
    "TLS_PSK_WITH_AES_128_GCM_SHA256": "0x00:0xA8",
    "TLS_PSK_WITH_AES_256_GCM_SHA384": "0x00:0xA9",
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256": "0x00:0xAA",
    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384": "0x00:0xAB",
    "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256": "0x00:0xAC",
    "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384": "0x00:0xAD",
    "TLS_PSK_WITH_AES_128_CBC_SHA256": "0x00:0xAE",
    "TLS_PSK_WITH_AES_256_CBC_SHA384": "0x00:0xAF",
    "TLS_PSK_WITH_NULL_SHA256": "0x00:0xB0",
    "TLS_PSK_WITH_NULL_SHA384": "0x00:0xB1",
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256": "0x00:0xB2",
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384": "0x00:0xB3",
    "TLS_DHE_PSK_WITH_NULL_SHA256": "0x00:0xB4",
    "TLS_DHE_PSK_WITH_NULL_SHA384": "0x00:0xB5",
    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256": "0x00:0xB6",
    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384": "0x00:0xB7",
    "TLS_RSA_PSK_WITH_NULL_SHA256": "0x00:0xB8",
    "TLS_RSA_PSK_WITH_NULL_SHA384": "0x00:0xB9",
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256": "0x00:0xBA",
    "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256": "0x00:0xBB",
    "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256": "0x00:0xBC",
    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256": "0x00:0xBD",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256": "0x00:0xBE",
    "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256": "0x00:0xBF",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256": "0x00:0xC0",
    "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256": "0x00:0xC1",
    "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256": "0x00:0xC2",
    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256": "0x00:0xC3",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256": "0x00:0xC4",
    "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256": "0x00:0xC5",
    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV": "0x00:0xFF",
    "TLS_ECDH_ECDSA_WITH_NULL_SHA": "0xC0:0x01",
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA": "0xC0:0x02",
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA": "0xC0:0x03",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA": "0xC0:0x04",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA": "0xC0:0x05",
    "TLS_ECDHE_ECDSA_WITH_NULL_SHA": "0xC0:0x06",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": "0xC0:0x07",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": "0xC0:0x08",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": "0xC0:0x09",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": "0xC0:0x0A",
    "TLS_ECDH_RSA_WITH_NULL_SHA": "0xC0:0x0B",
    "TLS_ECDH_RSA_WITH_RC4_128_SHA": "0xC0:0x0C",
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA": "0xC0:0x0D",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA": "0xC0:0x0E",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA": "0xC0:0x0F",
    "TLS_ECDHE_RSA_WITH_NULL_SHA": "0xC0:0x10",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA": "0xC0:0x11",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": "0xC0:0x12",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "0xC0:0x13",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": "0xC0:0x14",
    "TLS_ECDH_anon_WITH_NULL_SHA": "0xC0:0x15",
    "TLS_ECDH_anon_WITH_RC4_128_SHA": "0xC0:0x16",
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA": "0xC0:0x17",
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA": "0xC0:0x18",
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA": "0xC0:0x19",
    "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA": "0xC0:0x1A",
    "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA": "0xC0:0x1B",
    "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA": "0xC0:0x1C",
    "TLS_SRP_SHA_WITH_AES_128_CBC_SHA": "0xC0:0x1D",
    "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA": "0xC0:0x1E",
    "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA": "0xC0:0x1F",
    "TLS_SRP_SHA_WITH_AES_256_CBC_SHA": "0xC0:0x20",
    "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA": "0xC0:0x21",
    "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA": "0xC0:0x22",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": "0xC0:0x23",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": "0xC0:0x24",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256": "0xC0:0x25",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384": "0xC0:0x26",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": "0xC0:0x27",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": "0xC0:0x28",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256": "0xC0:0x29",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384": "0xC0:0x2A",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "0xC0:0x2B",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "0xC0:0x2C",
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256": "0xC0:0x2D",
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384": "0xC0:0x2E",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "0xC0:0x2F",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "0xC0:0x30",
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256": "0xC0:0x31",
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384": "0xC0:0x32",
    "TLS_ECDHE_PSK_WITH_RC4_128_SHA": "0xC0:0x33",
    "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA": "0xC0:0x34",
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA": "0xC0:0x35",
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA": "0xC0:0x36",
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256": "0xC0:0x37",
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384": "0xC0:0x38",
    "TLS_ECDHE_PSK_WITH_NULL_SHA": "0xC0:0x39",
    "TLS_ECDHE_PSK_WITH_NULL_SHA256": "0xC0:0x3A",
    "TLS_ECDHE_PSK_WITH_NULL_SHA384": "0xC0:0x3B",
    "TLS_RSA_WITH_ARIA_128_CBC_SHA256": "0xC0:0x3C",
    "TLS_RSA_WITH_ARIA_256_CBC_SHA384": "0xC0:0x3D",
    "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256": "0xC0:0x3E",
    "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384": "0xC0:0x3F",
    "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256": "0xC0:0x40",
    "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384": "0xC0:0x41",
    "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256": "0xC0:0x42",
    "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384": "0xC0:0x43",
    "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256": "0xC0:0x44",
    "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384": "0xC0:0x45",
    "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256": "0xC0:0x46",
    "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384": "0xC0:0x47",
    "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256": "0xC0:0x48",
    "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384": "0xC0:0x49",
    "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256": "0xC0:0x4A",
    "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384": "0xC0:0x4B",
    "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256": "0xC0:0x4C",
    "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384": "0xC0:0x4D",
    "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256": "0xC0:0x4E",
    "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384": "0xC0:0x4F",
    "TLS_RSA_WITH_ARIA_128_GCM_SHA256": "0xC0:0x50",
    "TLS_RSA_WITH_ARIA_256_GCM_SHA384": "0xC0:0x51",
    "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256": "0xC0:0x52",
    "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384": "0xC0:0x53",
    "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256": "0xC0:0x54",
    "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384": "0xC0:0x55",
    "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256": "0xC0:0x56",
    "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384": "0xC0:0x57",
    "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256": "0xC0:0x58",
    "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384": "0xC0:0x59",
    "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256": "0xC0:0x5A",
    "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384": "0xC0:0x5B",
    "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256": "0xC0:0x5C",
    "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384": "0xC0:0x5D",
    "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256": "0xC0:0x5E",
    "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384": "0xC0:0x5F",
    "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256": "0xC0:0x60",
    "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384": "0xC0:0x61",
    "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256": "0xC0:0x62",
    "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384": "0xC0:0x63",
    "TLS_PSK_WITH_ARIA_128_CBC_SHA256": "0xC0:0x64",
    "TLS_PSK_WITH_ARIA_256_CBC_SHA384": "0xC0:0x65",
    "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256": "0xC0:0x66",
    "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384": "0xC0:0x67",
    "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256": "0xC0:0x68",
    "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384": "0xC0:0x69",
    "TLS_PSK_WITH_ARIA_128_GCM_SHA256": "0xC0:0x6A",
    "TLS_PSK_WITH_ARIA_256_GCM_SHA384": "0xC0:0x6B",
    "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256": "0xC0:0x6C",
    "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384": "0xC0:0x6D",
    "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256": "0xC0:0x6E",
    "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384": "0xC0:0x6F",
    "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256": "0xC0:0x70",
    "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384": "0xC0:0x71",
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x72",
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x73",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x74",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x75",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x76",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x77",
    "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x78",
    "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x79",
    "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x7A",
    "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x7B",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x7C",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x7D",
    "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x7E",
    "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x7F",
    "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x80",
    "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x81",
    "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x82",
    "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x83",
    "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x84",
    "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x85",
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x86",
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x87",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x88",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x89",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x8A",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x8B",
    "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x8C",
    "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x8D",
    "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x8E",
    "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x8F",
    "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x90",
    "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x91",
    "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256": "0xC0:0x92",
    "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384": "0xC0:0x93",
    "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x94",
    "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x95",
    "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x96",
    "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x97",
    "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x98",
    "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x99",
    "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256": "0xC0:0x9A",
    "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384": "0xC0:0x9B",
    "TLS_RSA_WITH_AES_128_CCM": "0xC0:0x9C",
    "TLS_RSA_WITH_AES_256_CCM": "0xC0:0x9D",
    "TLS_DHE_RSA_WITH_AES_128_CCM": "0xC0:0x9E",
    "TLS_DHE_RSA_WITH_AES_256_CCM": "0xC0:0x9F",
    "TLS_RSA_WITH_AES_128_CCM_8": "0xC0:0xA0",
    "TLS_RSA_WITH_AES_256_CCM_8": "0xC0:0xA1",
    "TLS_DHE_RSA_WITH_AES_128_CCM_8": "0xC0:0xA2",
    "TLS_DHE_RSA_WITH_AES_256_CCM_8": "0xC0:0xA3",
    "TLS_PSK_WITH_AES_128_CCM": "0xC0:0xA4",
    "TLS_PSK_WITH_AES_256_CCM": "0xC0:0xA5",
    "TLS_DHE_PSK_WITH_AES_128_CCM": "0xC0:0xA6",
    "TLS_DHE_PSK_WITH_AES_256_CCM": "0xC0:0xA7",
    "TLS_PSK_WITH_AES_128_CCM_8": "0xC0:0xA8",
    "TLS_PSK_WITH_AES_256_CCM_8": "0xC0:0xA9",
    "TLS_PSK_DHE_WITH_AES_128_CCM_8": "0xC0:0xAA",
    "TLS_PSK_DHE_WITH_AES_256_CCM_8": "0xC0:0xAB",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM": "0xC0:0xAC",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM": "0xC0:0xAD",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8": "0xC0:0xAE",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8": "0xC0:0xAF",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "0xCC:0x14",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "0xCC:0x13",
}

inverse_tls_mapping = {v: k for k, v in tls_mapping.items()}

tls_version = {
    "3.0": 0x00,
    "1.0": 0x01,
    "1.1": 0x02,
    "1.2": 0x03,
    # This value for SSL 2.0 is completely non-standard. This is just a
    # convenience value I set for pretty-printing purposes.
    "2.0": -0x01,
}

inverse_tls_version = {v: k for k, v in tls_version.items()}


def int_to_hex_octet(value):
    return value // 256, value % 256


def get_cipher_value(list_of_ciphers):
    ciphers = []
    for cipher in list_of_ciphers:
        x, y = tls_mapping[cipher].split(":")
        ciphers.append(int(x, 0))
        ciphers.append(int(y, 0))
    return ciphers


def build_sni_extension(hostname):
    encoded_hostname = hostname.encode("idna")
    encoded_hostname_length = len(encoded_hostname)
    x, y = int_to_hex_octet(encoded_hostname_length)
    a, b = int_to_hex_octet(encoded_hostname_length + 3)
    j, k = int_to_hex_octet(encoded_hostname_length + 5)
    sni_extension = [
        0x00, 0x00,
        j, k, a, b,
        0x00,
        x, y
    ]

    sni_extension = sni_extension + list(encoded_hostname)
    return sni_extension


def build_ec_extension():
    ec_extensions = [
        # Extension: ec_point_formats
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        # Extension: elliptic_curves
        0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
        0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
        0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
        0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
        0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
        0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
    ]

    return ec_extensions


def build_compression_method(deflate=False):
    if deflate:
        compression_header = [
            0x02,             # Compression methods length
            0x01, 0x00,             # Compression method (0x00 for NULL)
        ]

    else:
        compression_header = [
            0x01,             # Compression methods length
            0x00,             # Compression method (0x00 for NULL)
        ]

    return compression_header


def build_client_hello(version, list_of_ciphers, hostname, deflate=False):
    cipher_list = get_cipher_value(list_of_ciphers)
    cipher_list = list(int_to_hex_octet(len(cipher_list))) + cipher_list
    cipher_length = len(cipher_list)

    compression_method = build_compression_method(deflate)
    compression_length = len(compression_method)

    # Compose extensions
    if tls_version[version] >= 0x01:
        sni_extension = build_sni_extension(hostname)
        sni_length = len(sni_extension)

        ec_extension = build_ec_extension()
        ec_length = len(ec_extension)

        extensions = (list(int_to_hex_octet(ec_length + sni_length)) +
                      ec_extension + sni_extension)
        extensions_length = len(extensions)

    else:
        extensions = [0x00, 0x00]
        extensions_length = len(extensions)

    # Various length values for the headers
    tls_header_length = int_to_hex_octet(
        cipher_length + compression_length + extensions_length + 35 + 4
    )
    handshake_header_length = int_to_hex_octet(
        cipher_length + compression_length + extensions_length + 35
    )

    x, y = tls_header_length
    tls_header = [
        0x16,             # Content type (0x16 for handshake)
        0x03, 0x00,       # TLS Version (0x0300 is SSLv3)
        x, y,             # Length (not including tls_header)
    ]

    x, y = handshake_header_length
    handshake_header = [
        0x01,             # Handshake Type (0x01 for ClientHello)
        0x00, x, y,       # Length of data to follow
        0x03, tls_version[version],
        # Random Bytes
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
        0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
        0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
        0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
        0x00,             # Session ID
    ]

    return (tls_header + handshake_header + cipher_list +
            compression_method + extensions)


def send_client_hello(host, port, client_hello):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(bytes(client_hello))
    tls_header = s.recv(5)

    # This is to handle the case where the server fails
    # to respond instead of a returning a handshake failure.
    # twitter.com does this if none of the cipher suites
    # specified by the client is supported.
    if len(tls_header) == 0:
        raise ValueError("Handshake Failed")

    response_length = (tls_header[3] * 256) + tls_header[4]
    return list(tls_header + s.recv(response_length))


def parse_server_hello(server_hello):
    if server_hello[0] == 0x15:
        raise ValueError("Handshake Failed")
    tls_version = server_hello[10]
    cipher_value = ("0x%02X" % server_hello[76] +
                    ":" + "0x%02X" % server_hello[77])
    cipher = inverse_tls_mapping[cipher_value]
    compression_method = server_hello[78]

    return tls_version, cipher, compression_method


def build_ssl2_client_hello():
    client_hello = [
        0x80, 0x2e,         # Length of record
        0x01,               # Handshake Type (0x01 for ClientHello)
        0x00, 0x02,
        0x00, 0x15,         # Length of cipher specs
        0x00, 0x00,         # Session ID Length
        0x00, 0x10,         # Challenge Length
        # Cipher Spec
        0x01, 0x00, 0x80,
        0x02, 0x00, 0x80,
        0x03, 0x00, 0x80,
        0x04, 0x00, 0x80,
        0x05, 0x00, 0x80,
        0x06, 0x00, 0x40,
        0x07, 0x00, 0xc0,
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
        0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
    ]

    return client_hello


def send_ssl2_client_hello(host, port, client_hello):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(bytes(client_hello))
        length_header = list(s.recv(2))

        # This is to handle the case where the server fails
        # to respond instead of a returning a handshake failure.
        # twitter.com does this if none of the cipher suites
        # specified by the client is supported.
        if len(length_header) == 0:
            raise ValueError("Handshake Failed")

        response_length = (length_header[0] - 128) * 256 + length_header[1]
        return length_header + list(s.recv(response_length))

    # Looks like some servers resets the connection when attempting to connect
    # using a SSLv2 ClientHello.
    except ConnectionResetError:
        raise ValueError("Handshake Failed")


def verify_certificate(host, port):
    from OpenSSL import SSL
    from service_identity import VerificationError
    from service_identity.pyopenssl import verify_hostname

    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_verify(
        SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok
    )
    ctx.set_default_verify_paths()

    conn = SSL.Connection(
        ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    )
    conn.connect((host, port))

    try:
        conn.do_handshake()
        verify_hostname(conn, host)
        return True

    except VerificationError:
        return False

    finally:
        conn.shutdown()
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="A command line tool to enumerate TLS cipher-suites "
                    "supported by a server.")
    parser.add_argument("host", type=str, help="Host to scan")
    parser.add_argument("port", type=int, help="Port number")
    parser.add_argument(
        "--verify-cert", action="store_true", dest="cert",
        help="Perform certificate verification"
    )
    args = parser.parse_args()

    cipher_list = list(tls_mapping.keys())
    supported_ciphers = []
    supported_tls_vers = []

    client_hello = build_ssl2_client_hello()
    try:
        send_ssl2_client_hello(args.host, args.port, client_hello)
        supported_tls_vers.append(tls_version["2.0"])
    except ValueError:
        pass

    for i in tls_version:
        try:
            client_hello = build_client_hello(
                i, cipher_list, args.host
            )
            server_hello = send_client_hello(
                args.host, args.port, client_hello
            )
            supported_tls_vers.append(parse_server_hello(server_hello)[0])
        except ValueError:
            continue

    supported_tls_vers = list(set(supported_tls_vers))
    supported_tls_vers.sort()

    print("TLS Versions supported by server: {0}".format(
        ", ".join([inverse_tls_version[x] for x in supported_tls_vers])
    ))

    client_hello = build_client_hello(
        "1.2", cipher_list, args.host, True
    )
    server_hello = send_client_hello(
        args.host, args.port, client_hello
    )
    compression = parse_server_hello(server_hello)[2]

    if compression == 1:
        print("Deflate compression: yes")
    else:
        print("Deflate compression: no")

    try:
        while len(cipher_list) > 0:
            client_hello = build_client_hello(
                "1.2", cipher_list, args.host
            )

            server_hello = send_client_hello(
                args.host, args.port, client_hello
            )
            cipher = parse_server_hello(server_hello)[1]

            supported_ciphers.append(cipher)
            cipher_list.remove(cipher)
    except ValueError:
        pass

    print("Supported Cipher suites in order of priority: ")
    for i in supported_ciphers:
        print(i)

    if args.cert:
        print("")
        try:
            if verify_certificate(args.host, args.port):
                print("Certificate is valid for {0}".format(args.host))
            else:
                print("Certificate is invalid for {0}".format(args.host))
        except ImportError:
            print("(--verify-cert) service_identity not installed.")

if __name__ == "__main__":
    main()
