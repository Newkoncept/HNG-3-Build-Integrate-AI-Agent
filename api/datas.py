daa = {
    "resultsPerPage": 42,
    "startIndex": 0,
    "totalResults": 42,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2025-11-03T03:14:28.805",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2012-5687",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2012-11-01T10:44:47.843",
                "lastModified": "2025-04-11T00:51:21.963",
                "vulnStatus": "Deferred",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Directory traversal vulnerability in the web-based management feature on the TP-LINK TL-WR841N router with firmware 3.13.9 build 120201 Rel.54965n and earlier allows remote attackers to read arbitrary files via a .. (dot dot) in the PATH_INFO to the help/ URI."
                    },
                    {
                        "lang": "es",
                        "value": "Una vulnerabilidad de salto de directorio en la función de administración web del Router TP-LINK TL-WR841N con firmware v3.13.9 build 120201 Rel.54965n y anteriores permite a atacantes remotos leer archivos de su elección a través de un .. (punto punto) en el PATH_INFO a la URI help/."
                    }
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:C/I:N/A:N",
                                "baseScore": 7.8,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "NONE"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10.0,
                            "impactScore": 6.9,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-22"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AD44582F-0CC5-4A71-8FE8-2BEF65EB717E"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "3.13.9",
                                        "matchCriteriaId": "12B0CF34-5A62-4D58-A82F-EB1049472670"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://archives.neohapsis.com/archives/bugtraq/2012-10/0154.html",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit"
                        ]
                    },
                    {
                        "url": "http://packetstormsecurity.org/files/117749/TP-LINK-TL-WR841N-Local-File-Inclusion.html",
                        "source": "cve@mitre.org"
                    },
                    {
                        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/79662",
                        "source": "cve@mitre.org"
                    },
                    {
                        "url": "http://archives.neohapsis.com/archives/bugtraq/2012-10/0154.html",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit"
                        ]
                    },
                    {
                        "url": "http://packetstormsecurity.org/files/117749/TP-LINK-TL-WR841N-Local-File-Inclusion.html",
                        "source": "af854a3a-2127-422b-91ae-364da2661108"
                    },
                    {
                        "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/79662",
                        "source": "af854a3a-2127-422b-91ae-364da2661108"
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2012-6276",
                "sourceIdentifier": "cret@cert.org",
                "published": "2013-01-26T21:55:00.960",
                "lastModified": "2025-04-11T00:51:21.963",
                "vulnStatus": "Deferred",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Directory traversal vulnerability in the web-based management interface on the TP-LINK TL-WR841N router with firmware 3.13.9 build 120201 Rel.54965n and earlier allows remote attackers to read arbitrary files via the URL parameter."
                    },
                    {
                        "lang": "es",
                        "value": "Vulnerabilidad de salto de directorio en el interfaz de gestión web del router TP-LINK TL-WR841N router con firmware v3.13.9 build 120201 Rel.54965n y anteriores, permite a atacantes remotos leer ficheros arbitrarios a través de un parámetro en la URL."
                    }
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                "baseScore": 4.3,
                                "accessVector": "NETWORK",
                                "accessComplexity": "MEDIUM",
                                "authentication": "NONE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "NONE"
                            },
                            "baseSeverity": "MEDIUM",
                            "exploitabilityScore": 8.6,
                            "impactScore": 2.9,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-22"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:3.13.9:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5DA3A384-7F8E-4B43-8F12-9C81EF409225"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AD44582F-0CC5-4A71-8FE8-2BEF65EB717E"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://www.kb.cert.org/vuls/id/185100",
                        "source": "cret@cert.org",
                        "tags": [
                            "US Government Resource"
                        ]
                    },
                    {
                        "url": "http://www.kb.cert.org/vuls/id/185100",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "US Government Resource"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2012-6316",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2014-09-30T14:55:07.970",
                "lastModified": "2025-04-12T10:46:40.837",
                "vulnStatus": "Deferred",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Multiple cross-site scripting (XSS) vulnerabilities in the TP-LINK TL-WR841N router with firmware 3.13.9 Build 120201 Rel.54965n and earlier allow remote administrators to inject arbitrary web script or HTML via the (1) username or (2) pwd parameter to userRpm/NoipDdnsRpm.htm."
                    },
                    {
                        "lang": "es",
                        "value": "Múltiples vulnerabilidades de XSS en el router TP-LINK TL-WR841N con firmware 3.13.9 Build 120201 Rel.54965n y anteriores permiten a administradores remotos inyectar secuencias de comandos web o HTML arbitrarios a través del parámetro (1) username o (2) pwd en userRpm/NoipDdnsRpm.htm."
                    }
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                                "baseScore": 4.3,
                                "accessVector": "NETWORK",
                                "accessComplexity": "MEDIUM",
                                "authentication": "NONE",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "NONE"
                            },
                            "baseSeverity": "MEDIUM",
                            "exploitabilityScore": 8.6,
                            "impactScore": 2.9,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": True
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-79"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "3.13.9",
                                        "matchCriteriaId": "12B0CF34-5A62-4D58-A82F-EB1049472670"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AD44582F-0CC5-4A71-8FE8-2BEF65EB717E"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://seclists.org/fulldisclosure/2012/Dec/93",
                        "source": "cve@mitre.org"
                    },
                    {
                        "url": "http://www.securityfocus.com/bid/56602",
                        "source": "cve@mitre.org"
                    },
                    {
                        "url": "http://seclists.org/fulldisclosure/2012/Dec/93",
                        "source": "af854a3a-2127-422b-91ae-364da2661108"
                    },
                    {
                        "url": "http://www.securityfocus.com/bid/56602",
                        "source": "af854a3a-2127-422b-91ae-364da2661108"
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2015-3035",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2015-04-22T01:59:02.553",
                "lastModified": "2025-10-22T00:15:42.857",
                "vulnStatus": "Deferred",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Directory traversal vulnerability in TP-LINK Archer C5 (1.2) with firmware before 150317, C7 (2.0) with firmware before 150304, and C8 (1.0) with firmware before 150316, Archer C9 (1.0), TL-WDR3500 (1.0), TL-WDR3600 (1.0), and TL-WDR4300 (1.0) with firmware before 150302, TL-WR740N (5.0) and TL-WR741ND (5.0) with firmware before 150312, and TL-WR841N (9.0), TL-WR841N (10.0), TL-WR841ND (9.0), and TL-WR841ND (10.0) with firmware before 150310 allows remote attackers to read arbitrary files via a .. (dot dot) in the PATH_INFO to login/."
                    },
                    {
                        "lang": "es",
                        "value": "Vulnerabilidad de salto de directorio en TP-LINK Archer C5 (1.2) con firmware anterior a 150317, C7 (2.0) con firmware anterior a 150304, y C8 (1.0) con firmware anterior a 150316, Archer C9 (1.0), TL-WDR3500 (1.0), TL-WDR3600 (1.0), y TL-WDR4300 (1.0) con firmware anterior a 150302, TL-WR740N (5.0) y TL-WR741ND (5.0) con firmware anterior a 150312, y TL-WR841N (9.0), TL-WR841N (10.0), TL-WR841ND (9.0), y TL-WR841ND (10.0) con firmware anterior a 150310 permite a atacantes remotos leer ficheros arbitrarios a través de un .. (punto punto) en PATH_INFO en login/."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "NONE"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "NONE"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:C/I:N/A:N",
                                "baseScore": 7.8,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "NONE"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10.0,
                            "impactScore": 6.9,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "cisaExploitAdd": "2022-03-25",
                "cisaActionDue": "2022-04-15",
                "cisaRequiredAction": "Apply updates per vendor instructions.",
                "cisaVulnerabilityName": "TP-Link Multiple Archer Devices Directory Traversal Vulnerability",
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-22"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-22"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_\\(9.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "06BFF5EB-63BD-489A-B108-12687B77A8F5"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n_\\(9.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "E80F84F8-528F-42C5-B19A-7D7428423C45"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_\\(5.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141217",
                                        "matchCriteriaId": "2CABC3A7-A089-4E79-BA39-39A76CE130DD"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n_\\(5.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "22721213-F1C6-4C2F-A64F-8792F093AE44"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:archer_c5_\\(1.2\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141126",
                                        "matchCriteriaId": "536D12F8-5DAC-49E4-ADC4-EFD8DF978663"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:archer_c5_\\(1.2\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1454B6DF-BC57-48B3-B2D5-D88F3E686A27"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_\\(10.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C092408D-3460-477A-B4D7-50BC3C266904"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n_\\(10.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "50C5C74F-62BD-4F6F-ABAE-48412AD4F798"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr741nd_\\(5.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141217",
                                        "matchCriteriaId": "65A32D8A-9823-440B-91A7-48B7F9610253"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr741nd_\\(5.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C448EFFF-A341-4D99-A9CD-CAFDB47C3B31"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wdr3600_\\(1.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141022",
                                        "matchCriteriaId": "D7835D28-9EAD-4C2A-B9B9-9C3AF0683C97"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wdr3600_\\(1.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "84CF3BA4-86A7-4638-96D7-3D94D46C1704"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:archer_c7_\\(2.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141110",
                                        "matchCriteriaId": "22CABB26-90EB-4C7D-BE8F-9974AF22626D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:archer_c7_\\(2.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AB54C1EF-B59B-4A8D-B65C-06D50DAA73FE"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_\\(10.0\\)_firmware:150104:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0946FFBF-4A32-43CB-A363-52941C507DEF"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd_\\(10.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "BFFF1AD6-B74A-4CBD-8245-18AEC3076CCB"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:archer_c9_\\(1.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "150122",
                                        "matchCriteriaId": "872B2B57-935A-4E1D-B240-BCE903490238"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:archer_c9_\\(1.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D832A00C-353A-4E30-BF32-7EC0853D05F6"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_\\(9.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "150104",
                                        "matchCriteriaId": "20C4D86E-B7DB-4FBD-96A9-37B5E7A2F8FC"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd_\\(9.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C43ECEF1-D76C-4ACE-B66E-964D491A8CB6"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:archer_c8_\\(1.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141023",
                                        "matchCriteriaId": "A667C76A-0FD1-450F-B6BA-69FDBE265096"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:archer_c8_\\(1.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "876FA83F-9F6E-4026-9B6F-FE788D494BD7"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wdr4300_\\(1.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141113",
                                        "matchCriteriaId": "AB308D99-45F3-41EA-B67D-A61513A93EA3"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wdr4300_\\(1.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "4707BF62-9AC3-498D-8460-0A5C2CC6E3C7"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wdr3500_\\(1.0\\)_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "141113",
                                        "matchCriteriaId": "F706E3CA-469F-4275-913D-C09A9B6BF1BD"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wdr3500_\\(1.0\\):-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "40E8FBA4-E296-4E4B-8BF2-14B08E34EE59"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://packetstormsecurity.com/files/131378/TP-LINK-Local-File-Disclosure.html",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "http://seclists.org/fulldisclosure/2015/Apr/26",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Mailing List",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "http://www.securityfocus.com/archive/1/535240/100/0/threaded",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "http://www.securityfocus.com/bid/74050",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C5_V1.20.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C7_V2.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C8_V1.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C9_V1.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WDR3500_V1.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WDR3600_V1.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WDR4300_V1.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR740N_V5.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR741ND_V5.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR841ND_V9.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR841N_V9.html#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20150410-0_TP-Link_Unauthenticated_local_file_disclosure_vulnerability_v10.txt",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Not Applicable"
                        ]
                    },
                    {
                        "url": "http://packetstormsecurity.com/files/131378/TP-LINK-Local-File-Disclosure.html",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "http://seclists.org/fulldisclosure/2015/Apr/26",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Mailing List",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "http://www.securityfocus.com/archive/1/535240/100/0/threaded",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "http://www.securityfocus.com/bid/74050",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C5_V1.20.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C7_V2.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C8_V1.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/Archer-C9_V1.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WDR3500_V1.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WDR3600_V1.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WDR4300_V1.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR740N_V5.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR741ND_V5.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR841ND_V9.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "http://www.tp-link.com/en/download/TL-WR841N_V9.html#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20150410-0_TP-Link_Unauthenticated_local_file_disclosure_vulnerability_v10.txt",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Not Applicable"
                        ]
                    },
                    {
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2015-3035",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0"
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2017-9466",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2017-06-26T07:29:00.340",
                "lastModified": "2025-04-20T01:37:25.860",
                "vulnStatus": "Deferred",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The executable httpd on the TP-Link WR841N V8 router before TL-WR841N(UN)_V8_170210 contained a design flaw in the use of DES for block encryption. This resulted in incorrect access control, which allowed attackers to gain read-write access to system settings through the protected router configuration service tddp via the LAN and Ath0 (Wi-Fi) interfaces."
                    },
                    {
                        "lang": "es",
                        "value": "El httpd ejecutable en el router TP-Link WR841N V8, en versiones anteriores a la TL-WR841N(UN)_V8_170210, contiene un fallo de diseño en el uso de DES para el cifrado en bloque. Esto resultó en un control de acceso incorrecto, lo que permitía que atacantes obtuviesen acceso de lectura-escritura a las opciones del sistema mediante el servicio de configuración del router protegido tddp mediante las interfaces LAN y Ath0 (Wi-Fi)."
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10.0,
                            "impactScore": 6.4,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-327"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:wr841n_v8_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "tl-wr841n_v8_140724",
                                        "matchCriteriaId": "27E9EF63-0C67-4BD3-8453-40CC03A662A8"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:wr841n_v8:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "19358DDB-F638-48C6-A68C-7476804C14DF"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://blog.senr.io/blog/cve-2017-9466-why-is-my-router-blinking-morse-code",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Technical Description",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "http://blog.senr.io/blog/cve-2017-9466-why-is-my-router-blinking-morse-code",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Technical Description",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2018-11714",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2018-06-04T14:29:00.500",
                "lastModified": "2024-11-21T03:43:52.910",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "An issue was discovered on TP-Link TL-WR840N v5 00000005 0.9.1 3.16 v0001.0 Build 170608 Rel.58696n and TL-WR841N v13 00000013 0.9.1 4.16 v0001.0 Build 170622 Rel.64334n devices. This issue is caused by improper session handling on the /cgi/ folder or a /cgi file. If an attacker sends a header of \"Referer: http://192.168.0.1/mainFrame.htm\" then no authentication is required for any action."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha descubierto un problema en los dispositivos TP-Link TL-WR840N v5 00000005 0.9.1 3.16 v0001.0 Build 170608 Rel.58696n y TL-WR841N v13 00000013 0.9.1 4.16 v0001.0 Build 170622 Rel.64334n. Este problema viene provocado por una gestión incorrecta de sesiones en la carpeta /cgi/ o un archivo /cgi. Si un atacante envía una cabecera \"Referer: http://192.168.0.1/mainFrame.htm\", no se requiere autenticación para llevar a cabo cualquier tipo de acción."
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                "baseScore": 10.0,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "COMPLETE",
                                "availabilityImpact": "COMPLETE"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10.0,
                            "impactScore": 10.0,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-384"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr840n_firmware:0.9.1_3.16:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7B9385FA-268B-4968-ACB7-6571900D56FA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr840n:5.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B2A8E1EF-87EB-4915-9E6E-0BF121AA9858"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:0.9.1_4.16:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DFC9F2FC-5E8B-4EE2-9B51-5F6A061E72B1"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:13.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F8E3FFDF-5026-4037-BF2F-0BF5D3E7EB26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://blog.securelayer7.net/time-to-disable-tp-link-home-wifi-router/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.exploit-db.com/exploits/44781/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "http://blog.securelayer7.net/time-to-disable-tp-link-home-wifi-router/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.exploit-db.com/exploits/44781/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2018-12574",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2018-07-02T16:29:00.443",
                "lastModified": "2024-11-21T03:45:27.623",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "CSRF exists for all actions in the web interface on TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n devices."
                    },
                    {
                        "lang": "es",
                        "value": "Existe CSRF para todas las acciones en la interfaz web en dispositivos TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n."
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "REQUIRED",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                                "baseScore": 6.8,
                                "accessVector": "NETWORK",
                                "accessComplexity": "MEDIUM",
                                "authentication": "NONE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL"
                            },
                            "baseSeverity": "MEDIUM",
                            "exploitabilityScore": 8.6,
                            "impactScore": 6.4,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": True
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-352"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:0.9.1_4.16:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DFC9F2FC-5E8B-4EE2-9B51-5F6A061E72B1"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:13.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F8E3FFDF-5026-4037-BF2F-0BF5D3E7EB26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://software-talk.org/blog/2018/06/tplink-wr841n-csrf-cve-2018-12574/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://software-talk.org/blog/2018/06/tplink-wr841n-csrf-cve-2018-12574/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2018-12575",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2018-07-02T16:29:00.490",
                "lastModified": "2024-11-21T03:45:27.770",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "On TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 171019 Rel.55346n devices, all actions in the web interface are affected by bypass of authentication via an HTTP request."
                    },
                    {
                        "lang": "es",
                        "value": "En dispositivos TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 171019 Rel.55346n, todas las acciones en la interfaz web se han visto afectadas por una omisión de autenticación mediante una petición HTTP."
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10.0,
                            "impactScore": 6.4,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-287"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:0.9.1_4.16:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DFC9F2FC-5E8B-4EE2-9B51-5F6A061E72B1"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:13.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F8E3FFDF-5026-4037-BF2F-0BF5D3E7EB26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://software-talk.org/blog/2018/06/tplink-wr841n-broken-auth-cve-2018-12575/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://software-talk.org/blog/2018/06/tplink-wr841n-broken-auth-cve-2018-12575/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2018-12576",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2018-07-02T16:29:00.520",
                "lastModified": "2024-11-21T03:45:27.917",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n devices allow clickjacking."
                    },
                    {
                        "lang": "es",
                        "value": "Los dispositivos TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n permiten el secuestro de clicks."
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                                "baseScore": 4.3,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "REQUIRED",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "LOW",
                                "availabilityImpact": "NONE"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 1.4
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                                "baseScore": 4.3,
                                "accessVector": "NETWORK",
                                "accessComplexity": "MEDIUM",
                                "authentication": "NONE",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "NONE"
                            },
                            "baseSeverity": "MEDIUM",
                            "exploitabilityScore": 8.6,
                            "impactScore": 2.9,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": True
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-1021"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:0.9.1_4.16:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DFC9F2FC-5E8B-4EE2-9B51-5F6A061E72B1"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:13.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F8E3FFDF-5026-4037-BF2F-0BF5D3E7EB26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://software-talk.org/blog/2018/04/tplink-wr841n-clickjacking-https/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://software-talk.org/blog/2018/04/tplink-wr841n-clickjacking-https/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2018-12577",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2018-07-02T16:29:00.553",
                "lastModified": "2024-11-21T03:45:28.050",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The Ping and Traceroute features on TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n devices allow authenticated blind Command Injection."
                    },
                    {
                        "lang": "es",
                        "value": "Las funcionalidades Ping y Traceroute en dispositivos TP-Link TL-WR841N v13 00000001 0.9.1 4.16 v0001.0 Build 180119 Rel.65243n permiten la inyección de comandos ciega autenticada."
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                                "baseScore": 6.5,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "SINGLE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL"
                            },
                            "baseSeverity": "MEDIUM",
                            "exploitabilityScore": 8.0,
                            "impactScore": 6.4,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-78"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:0.9.1_4.16:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DFC9F2FC-5E8B-4EE2-9B51-5F6A061E72B1"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:13.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F8E3FFDF-5026-4037-BF2F-0BF5D3E7EB26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://software-talk.org/blog/2018/06/tplink-wr841n-code-exec-cve-2018-12577/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://software-talk.org/blog/2018/06/tplink-wr841n-code-exec-cve-2018-12577/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2019-17147",
                "sourceIdentifier": "zdi-disclosures@trendmicro.com",
                "published": "2020-01-07T23:15:10.967",
                "lastModified": "2024-11-21T04:31:47.390",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "This vulnerability allows remote attackers to execute arbitrary code on affected installations of TP-LINK TL-WR841N routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the web service, which listens on TCP port 80 by default. When parsing the Host request header, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length static buffer. An attacker can leverage this vulnerability to execute code in the context of the admin user. Was ZDI-CAN-8457."
                    },
                    {
                        "lang": "es",
                        "value": "Esta vulnerabilidad permite a atacantes remotos ejecutar código arbitrario en las instalaciones afectadas de los routers TP-LINK TL-WR841N. No es requerida una autenticación para explotar esta vulnerabilidad. El fallo específico ocurre dentro del servicio web, que escucha sobre el puerto TCP 80 por defecto. Cuando se analiza el encabezado de petición Host, el proceso no comprueba apropiadamente la longitud de los datos suministrados por el usuario antes de copiarlos en un búfer estático de longitud fija. Un atacante puede aprovechar esta vulnerabilidad para ejecutar código en el contexto del usuario administrador. Fue ZDI-CAN-8457."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "REQUIRED",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV30": [
                        {
                            "source": "zdi-disclosures@trendmicro.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "ADJACENT_NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                "baseScore": 9.3,
                                "accessVector": "NETWORK",
                                "accessComplexity": "MEDIUM",
                                "authentication": "NONE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "COMPLETE",
                                "availabilityImpact": "COMPLETE"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 8.6,
                            "impactScore": 10.0,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": True
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "zdi-disclosures@trendmicro.com",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:0.9.1_4.16:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DFC9F2FC-5E8B-4EE2-9B51-5F6A061E72B1"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AD44582F-0CC5-4A71-8FE8-2BEF65EB717E"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.tp-link.com/us/support/download/tl-wr841n/#Firmware",
                        "source": "zdi-disclosures@trendmicro.com",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-19-992/",
                        "source": "zdi-disclosures@trendmicro.com",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/us/support/download/tl-wr841n/#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-19-992/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2020-8423",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2020-04-02T17:15:14.490",
                "lastModified": "2024-11-21T05:38:49.267",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow in the httpd daemon on TP-Link TL-WR841N V10 (firmware version 3.16.9) devices allows an authenticated remote attacker to execute arbitrary code via a GET request to the page for the configuration of the Wi-Fi network."
                    },
                    {
                        "lang": "es",
                        "value": "Un desbordamiento del búfer en el demonio httpd en los dispositivos TP-Link TL-WR841N versión V10 (versión de firmware 3.16.9), permite a un atacante remoto autenticado ejecutar código arbitrario por medio de una petición GET en la página para la configuración de la red Wi-Fi."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 7.2,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 1.2,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                "baseScore": 9.0,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "SINGLE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "COMPLETE",
                                "availabilityImpact": "COMPLETE"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 8.0,
                            "impactScore": 10.0,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:3.16.9:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B81E723C-539A-41E7-8486-A8263E9491F5"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v10:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "BDC4230D-3A3A-4D0E-BBD3-79C3054E90F8"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://ktln2.org/2020/03/29/exploiting-mips-router/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/us/security",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://ktln2.org/2020/03/29/exploiting-mips-router/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/us/security",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2020-35576",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2021-01-26T18:15:54.223",
                "lastModified": "2024-11-21T05:27:37.137",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A Command Injection issue in the traceroute feature on TP-Link TL-WR841N V13 (JP) with firmware versions prior to 201216 allows authenticated users to execute arbitrary code as root via shell metacharacters, a different vulnerability than CVE-2018-12577."
                    },
                    {
                        "lang": "es",
                        "value": "Un problema de Inyección de Comando en la funcionalidad traceroute en TP-Link TL-WR841N V13 (JP) con versiones de firmware anteriores a 201216, permite a usuarios autenticados ejecutar código arbitrario como root por medio de metacaracteres de shell, una vulnerabilidad diferente a CVE-2018-12577"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                "baseScore": 9.0,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "SINGLE",
                                "confidentialityImpact": "COMPLETE",
                                "integrityImpact": "COMPLETE",
                                "availabilityImpact": "COMPLETE"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 8.0,
                            "impactScore": 10.0,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-78"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "201216",
                                        "matchCriteriaId": "8A4AEC5C-05C5-458A-8F69-45686EFD56DA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v13:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "793E76A4-84C9-45DA-B9FE-85472C952F44"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://jvn.jp/en/vu/JVNVU92444096/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Patch",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr841n/v13/#Firmware",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Patch",
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/us/security",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://jvn.jp/en/vu/JVNVU92444096/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Patch",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr841n/v13/#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Patch",
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/us/security",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2022-0162",
                "sourceIdentifier": "vdisclose@cert-in.org.in",
                "published": "2022-02-09T23:15:16.513",
                "lastModified": "2024-11-21T06:38:02.873",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The vulnerability exists in TP-Link TL-WR841N V11 3.16.9 Build 160325 Rel.62500n wireless router due to transmission of authentication information in cleartextbase64 format. Successful exploitation of this vulnerability could allow a remote attacker to intercept credentials and subsequently perform administrative operations on the affected device through web-based management interface."
                    },
                    {
                        "lang": "es",
                        "value": "Se presenta una vulnerabilidad en el router inalámbrico TP-Link TL-WR841N versión V11 3.16.9 Build 160325 Rel.62500n, debido a una transmisión de información de autenticación en formato cleartextbase64. Una explotación con éxito de esta vulnerabilidad podría permitir a un atacante remoto interceptar las credenciales y posteriormente llevar a cabo operaciones administrativas en el dispositivo afectado mediante la interfaz de administración basada en web"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "vdisclose@cert-in.org.in",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.4,
                                "baseSeverity": "HIGH",
                                "attackVector": "LOCAL",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.5,
                            "impactScore": 5.9
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL"
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10.0,
                            "impactScore": 6.4,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "vdisclose@cert-in.org.in",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-319"
                            }
                        ]
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-319"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:3.16.9:build160325_rel.62500n:*:*:*:*:*:*",
                                        "matchCriteriaId": "B8EACBCC-F879-4BA0-B66D-79093935D3D7"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "508A2761-3DB2-4973-8B9C-22BE876EE987"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2022-0068",
                        "source": "vdisclose@cert-in.org.in",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2022-0068",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2022-30024",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2022-07-14T14:15:13.277",
                "lastModified": "2024-11-21T07:02:05.870",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow in the httpd daemon on TP-Link TL-WR841N V12 (firmware version 3.16.9) devices allows an authenticated remote attacker to execute arbitrary code via a GET request to the page for the System Tools of the Wi-Fi network. This affects TL-WR841 V12 TL-WR841N(EU)_V12_160624 and TL-WR841 V11 TL-WR841N(EU)_V11_160325 , TL-WR841N_V11_150616 and TL-WR841 V10 TL-WR841N_V10_150310 are also affected."
                    },
                    {
                        "lang": "es",
                        "value": "Un desbordamiento de búfer en el demonio httpd en los dispositivos TP-Link TL-WR841N V12 (versión de firmware 3.16.9) permite a un atacante remoto autenticado ejecutar código arbitrario por medio de una petición GET a la página de Herramientas del sistema de la red Wi-Fi. Esto afecta a los dispositivos TL-WR841 V12 TL-WR841N(EU)_V12_160624 y TL-WR841 V11 TL-WR841N(EU)_V11_160325 , TL-WR841N_V11_150616 y TL-WR841 V10 TL-WR841N_V10_150310 también están afectados"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "44B31977-DF82-44D4-B86D-06811BAD44EA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841:10:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1D0FF223-7AE0-4423-B291-A5E3624FE2E0"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "71CC9729-8915-4D0E-B1BC-63D494EEA021"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841:12:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "6C94F6B3-2160-4F2D-AFA4-B540AA3B7193"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:3.16.9:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B81E723C-539A-41E7-8486-A8263E9491F5"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:12:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "E855A3D8-9968-4DF9-890D-62028472A11B"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n\\(eu\\)_firmware:160325:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1F581106-3805-44B4-81B6-9C30D02DE3B6"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n\\(eu\\):11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F57BBF8C-693B-4249-8ACF-1FEE55D777D5"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:150616:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D129F04E-E5E0-47C8-82DF-4B782306BC9E"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "508A2761-3DB2-4973-8B9C-22BE876EE987"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:150310:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "8CB29067-7290-4B39-ABF8-4805BAF78804"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:10:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "605FA887-700C-4A7E-A253-E672D5554737"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "http://tl-wr841.com",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "URL Repurposed"
                        ]
                    },
                    {
                        "url": "http://tp-link.com",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://pastebin.com/0XRFr3zE",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "http://tl-wr841.com",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "URL Repurposed"
                        ]
                    },
                    {
                        "url": "http://tp-link.com",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://pastebin.com/0XRFr3zE",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2022-42202",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2022-10-18T13:15:10.587",
                "lastModified": "2025-05-13T15:15:50.800",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR841N 8.0 4.17.16 Build 120201 Rel.54750n is vulnerable to Cross Site Scripting (XSS)."
                    },
                    {
                        "lang": "es",
                        "value": "TP-Link TL-WR841N versión 8.0 4.17.16 Build 120201 Rel.54750n, es vulnerable a un ataque de tipo Cross Site Scripting (XSS)"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                "baseScore": 6.1,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "REQUIRED",
                                "scope": "CHANGED",
                                "confidentialityImpact": "LOW",
                                "integrityImpact": "LOW",
                                "availabilityImpact": "NONE"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 2.7
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                "baseScore": 6.1,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "REQUIRED",
                                "scope": "CHANGED",
                                "confidentialityImpact": "LOW",
                                "integrityImpact": "LOW",
                                "availabilityImpact": "NONE"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 2.7
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-79"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-79"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:4.17.16_build_120201_rel.54750n:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "296E9677-0322-40BA-939F-684EBA3B5385"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:8.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D1520C26-52D3-46E6-B11B-89C4085DDF23"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.yuque.com/docs/share/b85b8c6f-60ea-4d5c-acc5-3c4285806328",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.yuque.com/docs/share/b85b8c6f-60ea-4d5c-acc5-3c4285806328",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2022-46912",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2022-12-20T20:15:11.080",
                "lastModified": "2025-04-16T18:16:02.433",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "An issue in the firmware update process of TP-Link TL-WR841N / TL-WA841ND V7 3.13.9 and earlier allows attackers to execute arbitrary code or cause a Denial of Service (DoS) via uploading a crafted firmware image."
                    },
                    {
                        "lang": "es",
                        "value": "Un problema en el proceso de actualización de firmware de TP-Link TL-WR841N / TL-WA841ND V7 3.13.9 y anteriores permite a atacantes ejecutar código arbitrario o provocar una Denegación de Servicio (DoS) mediante la carga de una imagen de firmware manipulada."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "REQUIRED",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "REQUIRED",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "NVD-CWE-noinfo"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "3.13.9",
                                        "matchCriteriaId": "12B0CF34-5A62-4D58-A82F-EB1049472670"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AD44582F-0CC5-4A71-8FE8-2BEF65EB717E"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_v7_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "3.13.9",
                                        "matchCriteriaId": "05F0D098-707E-430C-961E-C8C0A12AF8D6"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd_v7:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "771A5B04-A342-4160-9319-FB23B50D30BA"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://hackmd.io/%40slASVrz_SrW7NQCsunofeA/Sk6sfbTPi",
                        "source": "cve@mitre.org"
                    },
                    {
                        "url": "https://www.tp-link.com/us/press/security-advisory/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    },
                    {
                        "url": "https://hackmd.io/%40slASVrz_SrW7NQCsunofeA/Sk6sfbTPi",
                        "source": "af854a3a-2127-422b-91ae-364da2661108"
                    },
                    {
                        "url": "https://www.tp-link.com/us/press/security-advisory/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2022-42433",
                "sourceIdentifier": "zdi-disclosures@trendmicro.com",
                "published": "2023-03-29T19:15:17.983",
                "lastModified": "2024-11-21T07:24:57.863",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link TL-WR841N TL-WR841N(US)_V14_220121 routers. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed. The specific flaw exists within the ated_tp service. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-17356."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.0,
                                "baseSeverity": "HIGH",
                                "attackVector": "ADJACENT_NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.1,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV30": [
                        {
                            "source": "zdi-disclosures@trendmicro.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 6.4,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "ADJACENT_NETWORK",
                                "attackComplexity": "HIGH",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 0.5,
                            "impactScore": 5.9
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "zdi-disclosures@trendmicro.com",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-78"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "220914",
                                        "matchCriteriaId": "7EFFF628-A63F-4522-909A-8A06339D45E2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AD44582F-0CC5-4A71-8FE8-2BEF65EB717E"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-22-1466/",
                        "source": "zdi-disclosures@trendmicro.com",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-22-1466/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-33536",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-07T04:15:10.467",
                "lastModified": "2025-01-07T16:15:31.153",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 was discovered to contain a buffer overflow via the component /userRpm/WlanMacFilterRpm."
                    },
                    {
                        "lang": "es",
                        "value": "Se descubrió que TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10 y TL-WR740N V1/V2 contenían un desbordamiento de búfer a través del componente /userRpm/WlanMacFilterRpm."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.2
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.2
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-125"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-125"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "68707068-83D6-460C-9107-1B86FC95F6DC"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:4.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "6212F19C-E507-43BC-B3F0-7DDABB84BE20"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:8.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D1520C26-52D3-46E6-B11B-89C4085DDF23"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:10.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "694B53D1-8714-4678-A9CF-51FF230C8BC4"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "13CA99B0-BE20-4850-9D5E-2CC6020C4775"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:1.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "6284AB5D-17FD-411B-99A1-948434193041"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5E7D2E14-77D8-4534-BBD1-D52ADA5B175F"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/2/TL-WR940N_TL-WR841N_TL-WR740N_userRpm_WlanMacFilterRpm.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/2/TL-WR940N_TL-WR841N_TL-WR740N_userRpm_WlanMacFilterRpm.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-33537",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-07T04:15:10.563",
                "lastModified": "2025-01-07T16:15:31.423",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 was discovered to contain a buffer overflow via the component /userRpm/FixMapCfgRpm."
                    },
                    {
                        "lang": "es",
                        "value": "Se descubrió que TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10 y TL-WR740N V1/V2 contenían un desbordamiento de búfer a través del componente /userRpm/FixMapCfgRpm."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.2
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.2
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-125"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-125"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "68707068-83D6-460C-9107-1B86FC95F6DC"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:4.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "6212F19C-E507-43BC-B3F0-7DDABB84BE20"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:8.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D1520C26-52D3-46E6-B11B-89C4085DDF23"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:10.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "694B53D1-8714-4678-A9CF-51FF230C8BC4"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "13CA99B0-BE20-4850-9D5E-2CC6020C4775"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:1.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "6284AB5D-17FD-411B-99A1-948434193041"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5E7D2E14-77D8-4534-BBD1-D52ADA5B175F"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/1/TL-WR940N_TL-WR841N_TL-WR740N_userRpm_FixMapCfgRpm.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/1/TL-WR940N_TL-WR841N_TL-WR740N_userRpm_FixMapCfgRpm.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-33538",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-07T04:15:10.623",
                "lastModified": "2025-10-27T14:32:16.313",
                "vulnStatus": "Analyzed",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 was discovered to contain a command injection vulnerability via the component /userRpm/WlanNetworkRpm ."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha descubierto que TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, y TL-WR740N V1/V2 contienen una vulnerabilidad de inyección de comandos en el componente /userRpm/WlanNetworkRpm."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ]
                },
                "cisaExploitAdd": "2025-06-16",
                "cisaActionDue": "2025-07-07",
                "cisaRequiredAction": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
                "cisaVulnerabilityName": "TP-Link Multiple Routers Command Injection Vulnerability",
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-77"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-77"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "68707068-83D6-460C-9107-1B86FC95F6DC"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:4.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "6212F19C-E507-43BC-B3F0-7DDABB84BE20"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:8.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D1520C26-52D3-46E6-B11B-89C4085DDF23"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:10.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "694B53D1-8714-4678-A9CF-51FF230C8BC4"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "13CA99B0-BE20-4850-9D5E-2CC6020C4775"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:1.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "6284AB5D-17FD-411B-99A1-948434193041"
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5E7D2E14-77D8-4534-BBD1-D52ADA5B175F"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/3/TL-WR940N_TL-WR841N_userRpm_WlanNetworkRpm_Command_Injection.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link",
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://web.archive.org/web/20230609111043/https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/3/TL-WR940N_TL-WR841N_userRpm_WlanNetworkRpm_Command_Injection.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.secpod.com/blog/cisa-issues-warning-on-active-exploitation-of-tp-link-vulnerability-cve-2023-33538/",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/3/TL-WR940N_TL-WR841N_userRpm_WlanNetworkRpm_Command_Injection.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Broken Link",
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://web.archive.org/web/20230609111043/https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/3/TL-WR940N_TL-WR841N_userRpm_WlanNetworkRpm_Command_Injection.md",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-33538",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "US Government Resource"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/us/support/faq/3562/",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "Product"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-36354",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-22T20:15:09.687",
                "lastModified": "2024-11-21T08:09:34.943",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V4, TL-WR841N V8/V10, TL-WR740N V1/V2, TL-WR940N V2/V3, and TL-WR941ND V5/V6 were discovered to contain a buffer overflow in the component /userRpm/AccessCtrlTimeSchedRpm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted GET request."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2537DC7E-8024-45B5-924C-18C9B702DAFC"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v8:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2F9738A0-4CC4-4C8C-A4BA-843395B0AA55"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v10:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "BDC4230D-3A3A-4D0E-BBD3-79C3054E90F8"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "13CA99B0-BE20-4850-9D5E-2CC6020C4775"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:v1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "89AF2EC8-F679-4A9D-BB1C-E3EABCC7A086"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "13CA99B0-BE20-4850-9D5E-2CC6020C4775"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:v2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "19CA5AB9-F342-4E8D-9658-569198DDE8F9"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "029B4B03-94CE-41FF-A635-41682AE4B26D"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v3:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DF722F24-7D43-4535-B013-545109CB1D98"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v5:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1B0FC0E0-6C5B-49CA-95E3-D4AAC9D51518"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v6:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "111123CC-8945-4BB2-AD6B-08E80B1A2AD6"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/7/TL-WR940N_TL-WR841N_TL-WR740N_TL-WR941ND_userRpm_AccessCtrlTimeSchedRpm.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/7/TL-WR940N_TL-WR841N_TL-WR740N_TL-WR941ND_userRpm_AccessCtrlTimeSchedRpm.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-36356",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-22T20:15:09.780",
                "lastModified": "2024-11-21T08:09:35.277",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V2/V4/V6, TL-WR841N V8, TL-WR941ND V5, and TL-WR740N V1/V2 were discovered to contain a buffer read out-of-bounds via the component /userRpm/VirtualServerRpm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted GET request."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H",
                                "baseScore": 7.7,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.1,
                            "impactScore": 4.0
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-125"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2537DC7E-8024-45B5-924C-18C9B702DAFC"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v8:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2F9738A0-4CC4-4C8C-A4BA-843395B0AA55"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "13CA99B0-BE20-4850-9D5E-2CC6020C4775"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:v1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "89AF2EC8-F679-4A9D-BB1C-E3EABCC7A086"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr740n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "13CA99B0-BE20-4850-9D5E-2CC6020C4775"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr740n:v2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "19CA5AB9-F342-4E8D-9658-569198DDE8F9"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "029B4B03-94CE-41FF-A635-41682AE4B26D"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v5:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1B0FC0E0-6C5B-49CA-95E3-D4AAC9D51518"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v6:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "714E7A62-634A-4DF8-B5AF-D6B306808B54"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/4/TL-WR941ND_TL-WR940N_TL-WR740N_userRpm_VirtualServerRpm.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/4/TL-WR941ND_TL-WR940N_TL-WR740N_userRpm_VirtualServerRpm.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-36357",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-22T20:15:09.823",
                "lastModified": "2024-12-02T19:15:07.480",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "An issue in the /userRpm/LocalManageControlRpm component of TP-Link TL-WR940N V2/V4/V6, TL-WR841N V8/V10, and TL-WR941ND V5 allows attackers to cause a Denial of Service (DoS) via a crafted GET request."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H",
                                "baseScore": 7.7,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.1,
                            "impactScore": 4.0
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "NVD-CWE-noinfo"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-770"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2537DC7E-8024-45B5-924C-18C9B702DAFC"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v8:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2F9738A0-4CC4-4C8C-A4BA-843395B0AA55"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v10:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "BDC4230D-3A3A-4D0E-BBD3-79C3054E90F8"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "029B4B03-94CE-41FF-A635-41682AE4B26D"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v5:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1B0FC0E0-6C5B-49CA-95E3-D4AAC9D51518"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v6:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "714E7A62-634A-4DF8-B5AF-D6B306808B54"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/5/TL-WR941ND_TL-WR940N_TL-WR841N_userRpm_LocalManageControlRpm.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/5/TL-WR941ND_TL-WR940N_TL-WR841N_userRpm_LocalManageControlRpm.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-36358",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-22T20:15:09.873",
                "lastModified": "2024-12-10T22:15:05.393",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V2/V3/V4, TL-WR941ND V5/V6, TL-WR743ND V1 and TL-WR841N V8 were discovered to contain a buffer overflow in the component /userRpm/AccessCtrlAccessTargetsRpm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted GET request."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H",
                                "baseScore": 7.7,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.1,
                            "impactScore": 4.0
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H",
                                "baseScore": 7.7,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.1,
                            "impactScore": 4.0
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2537DC7E-8024-45B5-924C-18C9B702DAFC"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v8:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2F9738A0-4CC4-4C8C-A4BA-843395B0AA55"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "029B4B03-94CE-41FF-A635-41682AE4B26D"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v3:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DF722F24-7D43-4535-B013-545109CB1D98"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v5:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1B0FC0E0-6C5B-49CA-95E3-D4AAC9D51518"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v6:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "111123CC-8945-4BB2-AD6B-08E80B1A2AD6"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr743nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "3E9AD6E6-39EE-4A07-BBD7-5C48257A8689"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr743nd:v1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "E5056D9C-BCA3-4361-AB19-686875E5C123"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/6/TL-WR940N_WR941ND_WR743ND_WR841N_userRpm_AccessCtrlAccessTargetsRpm.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/6/TL-WR940N_WR941ND_WR743ND_WR841N_userRpm_AccessCtrlAccessTargetsRpm.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-36359",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-06-22T20:15:09.920",
                "lastModified": "2024-12-10T21:15:14.750",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V4, TL-WR841N V8/V10, TL-WR940N V2/V3 and TL-WR941ND V5/V6 were discovered to contain a buffer overflow in the component /userRpm/QoSRuleListRpm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted GET request."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2537DC7E-8024-45B5-924C-18C9B702DAFC"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v8:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2F9738A0-4CC4-4C8C-A4BA-843395B0AA55"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F7F95370-1001-4194-A0CB-B3CEA027AB6D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v10:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "BDC4230D-3A3A-4D0E-BBD3-79C3054E90F8"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "029B4B03-94CE-41FF-A635-41682AE4B26D"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v3:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DF722F24-7D43-4535-B013-545109CB1D98"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v5:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1B0FC0E0-6C5B-49CA-95E3-D4AAC9D51518"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "7600C377-2A63-4127-8958-32E04E7983CA"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd:v6:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "111123CC-8945-4BB2-AD6B-08E80B1A2AD6"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/8/TP-Link%20TL-WR940N%20TL-WR841N%20TL-WR941ND%20wireless%20router%20userRpmQoSRuleListRpm%20buffer%20read%20out-of-bounds%20vulnerability.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/8/TP-Link%20TL-WR940N%20TL-WR841N%20TL-WR941ND%20wireless%20router%20userRpmQoSRuleListRpm%20buffer%20read%20out-of-bounds%20vulnerability.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/8/TP-Link%20TL-WR940N%20TL-WR841N%20TL-WR941ND%20wireless%20router%20userRpmQoSRuleListRpm%20buffer%20read%20out-of-bounds%20vulnerability.md",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-39745",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-08-21T03:15:11.487",
                "lastModified": "2024-11-21T08:15:54.753",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR940N V2, TP-Link TL-WR941ND V5 and TP-Link TL-WR841N V8 were discovered to contain a buffer overflow via the component /userRpm/AccessCtrlAccessRulesRpm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted GET request."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_v2_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "465D8E81-9D1D-4F1E-8286-A20FA254B28D"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n_v2:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "1F279E7C-77BB-419B-97F4-378392560828"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr941nd_v5_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "072943A3-C949-4C5B-B5CC-6CC4CD0CCEC1"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr941nd_v5:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0C3923D0-6ED5-491C-B5CE-9933FF08F63E"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_v8_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0CDB9597-BB6D-457D-B609-85A564C3037E"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n_v8:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C92B3785-F0A1-444A-A3D0-3E0ADCE31170"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/16/TP-Link%20WR940N%20WR941ND%20WR841N%20wireless%20router%20userRpmAccessCtrlAccessRulesRpm%20buffer%20read%20out-of-bounds%20vulnerability.md",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/a101e-IoTvul/iotvul/blob/main/tp-link/16/TP-Link%20WR940N%20WR941ND%20WR841N%20wireless%20router%20userRpmAccessCtrlAccessRulesRpm%20buffer%20read%20out-of-bounds%20vulnerability.md",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-36489",
                "sourceIdentifier": "vultures@jpcert.or.jp",
                "published": "2023-09-06T10:15:13.710",
                "lastModified": "2024-11-21T08:09:49.150",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Multiple TP-LINK products allow a network-adjacent unauthenticated attacker to execute arbitrary OS commands. Affected products/versions are as follows: TL-WR802N firmware versions prior to 'TL-WR802N(JP)_V4_221008', TL-WR841N firmware versions prior to 'TL-WR841N(JP)_V14_230506', and TL-WR902AC firmware versions prior to 'TL-WR902AC(JP)_V3_230506'."
                    },
                    {
                        "lang": "es",
                        "value": "Múltiples productos TP-LINK permiten que un atacante no autenticado adyacente a la red ejecute comandos arbitrarios del sistema operativo. Los productos/versiones afectados son los siguientes: versiones de firmware del TL-WR802N anteriores a 'TL-WR802N(JP)_V4_221008', versiones de firmware del TL-WR841N anteriores a 'TL-WR841N(JP)_V14_230506' y versiones de firmware del TL-WR902AC anteriores a 'TL-WR902AC(JP)_V3_230506'.\n"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "ADJACENT_NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-78"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr902ac_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "230506",
                                        "matchCriteriaId": "3376E9AB-5749-4129-BF47-B9378E073B5A"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr902ac:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5541D281-8231-4724-BF9B-4E0FF61215A0"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr802n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "221008",
                                        "matchCriteriaId": "EC40A74F-6DCC-4DEB-A38F-D293BE80303F"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr802n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2E1B4F55-1FCF-4557-A051-2EBC1414DD00"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "230506",
                                        "matchCriteriaId": "93ED2916-46C6-43BE-A163-4AC82874869A"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AD44582F-0CC5-4A71-8FE8-2BEF65EB717E"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://jvn.jp/en/vu/JVNVU99392903/",
                        "source": "vultures@jpcert.or.jp",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr802n/#Firmware",
                        "source": "vultures@jpcert.or.jp",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr841n/v14/#Firmware",
                        "source": "vultures@jpcert.or.jp",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr902ac/#Firmware",
                        "source": "vultures@jpcert.or.jp",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://jvn.jp/en/vu/JVNVU99392903/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr802n/#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr841n/v14/#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/jp/support/download/tl-wr902ac/#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-39471",
                "sourceIdentifier": "zdi-disclosures@trendmicro.com",
                "published": "2024-05-03T03:15:12.903",
                "lastModified": "2025-08-12T15:45:58.070",
                "vulnStatus": "Analyzed",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR841N ated_tp Command Injection Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link TL-WR841N routers. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the ated_tp service. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-21825."
                    },
                    {
                        "lang": "es",
                        "value": "TP-Link TL-WR841N Vulnerabilidad de ejecución remota de código de inyección de comando ated_tp. Esta vulnerabilidad permite a atacantes adyacentes a la red ejecutar código arbitrario en las instalaciones afectadas de los enrutadores TP-Link TL-WR841N. No se requiere autenticación para aprovechar esta vulnerabilidad. La falla específica existe dentro del servicio ated_tp. El problema se debe a la falta de validación adecuada de una cadena proporcionada por el usuario antes de usarla para ejecutar una llamada al sistema. Un atacante puede aprovechar esta vulnerabilidad para ejecutar código en el contexto de la raíz. Era ZDI-CAN-21825."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "ADJACENT_NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV30": [
                        {
                            "source": "zdi-disclosures@trendmicro.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "ADJACENT_NETWORK",
                                "attackComplexity": "HIGH",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 1.6,
                            "impactScore": 5.9
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "zdi-disclosures@trendmicro.com",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-78"
                            }
                        ]
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-77"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "231119",
                                        "matchCriteriaId": "4E4FACFD-3AD3-4A6F-8B56-494208A050F5"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:v14:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "883F1571-DD41-4833-BA4A-EA370F21F07C"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr840n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "231121",
                                        "matchCriteriaId": "8BB0039F-2E92-44DC-9AE5-6D1AE9294E79"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr840n:6.20:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B1CB92AF-1C4E-45EC-B1E6-71046F1E6008"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-23-1624/",
                        "source": "zdi-disclosures@trendmicro.com",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-23-1624/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-50224",
                "sourceIdentifier": "zdi-disclosures@trendmicro.com",
                "published": "2024-05-03T03:16:10.833",
                "lastModified": "2025-10-27T17:05:21.053",
                "vulnStatus": "Analyzed",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "TP-Link TL-WR841N dropbearpwd Improper Authentication Information Disclosure Vulnerability. This vulnerability allows network-adjacent attackers to disclose sensitive information on affected installations of TP-Link TL-WR841N routers. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the httpd service, which listens on TCP port 80 by default. The issue results from improper authentication. An attacker can leverage this vulnerability to disclose stored credentials, leading to further compromise.\n. Was ZDI-CAN-19899."
                    },
                    {
                        "lang": "es",
                        "value": "TP-Link TL-WR841N dropbearpwd Vulnerabilidad de divulgación de información de autenticación incorrecta. Esta vulnerabilidad permite a atacantes adyacentes a la red revelar información confidencial sobre las instalaciones afectadas de los enrutadores TP-Link TL-WR841N. No se requiere autenticación para aprovechar esta vulnerabilidad. La falla específica existe dentro del servicio httpd, que escucha en el puerto TCP 80 de forma predeterminada. El problema se debe a una autenticación incorrecta. Un atacante puede aprovechar esta vulnerabilidad para revelar las credenciales almacenadas, lo que provocaría un mayor commit. Fue ZDI-CAN-19899."
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "zdi-disclosures@trendmicro.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "ADJACENT_NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "NONE"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 3.6
                        }
                    ]
                },
                "cisaExploitAdd": "2025-09-03",
                "cisaActionDue": "2025-09-24",
                "cisaRequiredAction": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
                "cisaVulnerabilityName": "TP-Link TL-WR841N Authentication Bypass by Spoofing Vulnerability",
                "weaknesses": [
                    {
                        "source": "zdi-disclosures@trendmicro.com",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-290"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:3.16.9:build_200409:*:*:*:*:*:*",
                                        "matchCriteriaId": "02C7E519-F7A1-419F-BD07-B919A21E966E"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:12:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "E855A3D8-9968-4DF9-890D-62028472A11B"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.tp-link.com/en/support/download/tl-wr841n/v12/#Firmware",
                        "source": "zdi-disclosures@trendmicro.com",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-23-1808/",
                        "source": "zdi-disclosures@trendmicro.com",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/en/support/download/tl-wr841n/v12/#Firmware",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Product"
                        ]
                    },
                    {
                        "url": "https://www.zerodayinitiative.com/advisories/ZDI-23-1808/",
                        "source": "af854a3a-2127-422b-91ae-364da2661108",
                        "tags": [
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-50224",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "US Government Resource"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2024-9284",
                "sourceIdentifier": "cna@vuldb.com",
                "published": "2024-09-27T17:15:14.600",
                "lastModified": "2025-07-15T18:29:21.443",
                "vulnStatus": "Analyzed",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability was found in TP-LINK TL-WR841ND up to 20240920. It has been rated as critical. Affected by this issue is some unknown functionality of the file /userRpm/popupSiteSurveyRpm.htm. The manipulation of the argument ssid leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha encontrado una vulnerabilidad en TP-LINK TL-WR841ND hasta 20240920. Se ha calificado como crítica. Este problema afecta a algunas funciones desconocidas del archivo /userRpm/popupSiteSurveyRpm.htm. La manipulación del argumento ssid provoca un desbordamiento del búfer basado en la pila. El ataque puede ejecutarse de forma remota. El exploit se ha divulgado al público y puede utilizarse. Se contactó primeramente con el proveedor sobre esta divulgación, pero no respondió de ninguna manera."
                    }
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "cna@vuldb.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                "baseScore": 7.1,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "NONE",
                                "vulnIntegrityImpact": "NONE",
                                "vulnAvailabilityImpact": "HIGH",
                                "subConfidentialityImpact": "NONE",
                                "subIntegrityImpact": "NONE",
                                "subAvailabilityImpact": "NONE",
                                "exploitMaturity": "NOT_DEFINED",
                                "confidentialityRequirement": "NOT_DEFINED",
                                "integrityRequirement": "NOT_DEFINED",
                                "availabilityRequirement": "NOT_DEFINED",
                                "modifiedAttackVector": "NOT_DEFINED",
                                "modifiedAttackComplexity": "NOT_DEFINED",
                                "modifiedAttackRequirements": "NOT_DEFINED",
                                "modifiedPrivilegesRequired": "NOT_DEFINED",
                                "modifiedUserInteraction": "NOT_DEFINED",
                                "modifiedVulnConfidentialityImpact": "NOT_DEFINED",
                                "modifiedVulnIntegrityImpact": "NOT_DEFINED",
                                "modifiedVulnAvailabilityImpact": "NOT_DEFINED",
                                "modifiedSubConfidentialityImpact": "NOT_DEFINED",
                                "modifiedSubIntegrityImpact": "NOT_DEFINED",
                                "modifiedSubAvailabilityImpact": "NOT_DEFINED",
                                "Safety": "NOT_DEFINED",
                                "Automatable": "NOT_DEFINED",
                                "Recovery": "NOT_DEFINED",
                                "valueDensity": "NOT_DEFINED",
                                "vulnerabilityResponseEffort": "NOT_DEFINED",
                                "providerUrgency": "NOT_DEFINED"
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "source": "cna@vuldb.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 3.6
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "cna@vuldb.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:S/C:N/I:N/A:C",
                                "baseScore": 6.8,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "SINGLE",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "COMPLETE"
                            },
                            "baseSeverity": "MEDIUM",
                            "exploitabilityScore": 8.0,
                            "impactScore": 6.9,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "cna@vuldb.com",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-121"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "60843636-698C-4000-84CB-9D441601EDE2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "8271D2EC-2B5E-49C2-824C-8F2C564B97C2"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/abcdefg-png/IoT-vulnerable/blob/main/TP-LINK/WR-841ND/popupSiteSurveyRpm.md",
                        "source": "cna@vuldb.com",
                        "tags": [
                            "Broken Link"
                        ]
                    },
                    {
                        "url": "https://vuldb.com/?ctiid.278684",
                        "source": "cna@vuldb.com",
                        "tags": [
                            "Permissions Required",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://vuldb.com/?id.278684",
                        "source": "cna@vuldb.com",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://vuldb.com/?submit.411526",
                        "source": "cna@vuldb.com",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/",
                        "source": "cna@vuldb.com",
                        "tags": [
                            "Product"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-25897",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2025-02-13T16:16:49.790",
                "lastModified": "2025-03-18T16:15:27.567",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow vulnerability was discovered in TP-Link TL-WR841ND V11 via the 'ip' parameter at /userRpm/WanStaticIpV6CfgRpm.htm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted packet."
                    },
                    {
                        "lang": "es",
                        "value": "Se descubrió una vulnerabilidad de desbordamiento de búfer en TP-Link TL-WR841ND V11 a través del parámetro 'ip' en /userRpm/WanStaticIpV6CfgRpm.htm. Esta vulnerabilidad permite a los atacantes provocar una denegación de servicio (DoS) a través de un paquete manipulado."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-787"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-787"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "60843636-698C-4000-84CB-9D441601EDE2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd:v11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0B6B17A5-94C4-4B4C-998A-B0B7B7FADB21"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/2664521593/mycve/blob/main/TP-Link/BOF_in_TP-Link_TL-WR841ND-V11_3.pdf",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-25898",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2025-02-13T16:16:49.867",
                "lastModified": "2025-03-18T14:15:43.617",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow vulnerability was discovered in TP-Link TL-WR841ND V11 via the pskSecret parameter at /userRpm/WlanSecurityRpm.htm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted packet."
                    },
                    {
                        "lang": "es",
                        "value": "Se descubrió una vulnerabilidad de desbordamiento de búfer en TP-Link TL-WR841ND V11 a través del parámetro pskSecret en /userRpm/WlanSecurityRpm.htm. Esta vulnerabilidad permite a los atacantes provocar una denegación de servicio (DoS) a través de un paquete manipulado."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-787"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-787"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "60843636-698C-4000-84CB-9D441601EDE2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd:v11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0B6B17A5-94C4-4B4C-998A-B0B7B7FADB21"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/2664521593/mycve/blob/main/TP-Link/BOF_in_TP-Link_TL-WR841ND-V11_1.pdf",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-25899",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2025-02-13T16:16:49.953",
                "lastModified": "2025-06-20T17:26:06.423",
                "vulnStatus": "Analyzed",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow vulnerability was discovered in TP-Link TL-WR841ND V11 via the 'gw' parameter at /userRpm/WanDynamicIpV6CfgRpm.htm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted packet."
                    },
                    {
                        "lang": "es",
                        "value": "Se descubrió una vulnerabilidad de desbordamiento de búfer en TP-Link TL-WR841ND V11 a través del parámetro 'gw' en /userRpm/WanDynamicIpV6CfgRpm.htm. Esta vulnerabilidad permite a los atacantes provocar una denegación de servicio (DoS) a través de un paquete manipulado."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:L",
                                "baseScore": 3.5,
                                "baseSeverity": "LOW",
                                "attackVector": "NETWORK",
                                "attackComplexity": "HIGH",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "LOW"
                            },
                            "exploitabilityScore": 1.8,
                            "impactScore": 1.4
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-404"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_v11_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "FA9094C6-F936-4CDF-B7F5-542DFB76A3C0"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd_v11:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5F4E2ECB-786B-44C2-90FC-14FC73BDD0C3"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/2664521593/mycve/blob/main/TP-Link/BOF_in_TP-Link_TL-WR841ND-V11_2.pdf",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-25900",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2025-02-13T16:16:50.037",
                "lastModified": "2025-06-20T17:25:56.670",
                "vulnStatus": "Analyzed",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow vulnerability was discovered in TP-Link TL-WR841ND V11 via the username and password parameters at /userRpm/PPPoEv6CfgRpm.htm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted packet."
                    },
                    {
                        "lang": "es",
                        "value": "Se descubrió una vulnerabilidad de desbordamiento de búfer en TP-Link TL-WR841ND V11 a través de los parámetros de nombre de usuario y contraseña en /userRpm/PPPoEv6CfgRpm.htm. Esta vulnerabilidad permite a los atacantes provocar una denegación de servicio (DoS) a través de un paquete manipulado."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 4.9,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 1.2,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_v11_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "FA9094C6-F936-4CDF-B7F5-542DFB76A3C0"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd_v11:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5F4E2ECB-786B-44C2-90FC-14FC73BDD0C3"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/2664521593/mycve/blob/main/TP-Link/BOF_in_TP-Link_TL-WR841ND-V11_4.pdf",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Broken Link"
                        ]
                    },
                    {
                        "url": "https://github.com/2664521593/mycve/blob/main/TP-Link/BOF_in_TP-Link_TL-WR841ND-V11_4.pdf",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "Broken Link"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-25901",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2025-02-13T16:16:50.180",
                "lastModified": "2025-02-20T15:15:14.380",
                "vulnStatus": "Modified",
                "cveTags": [],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow vulnerability was discovered in TP-Link TL-WR841ND V11, triggered by the dnsserver1 and dnsserver2 parameters at /userRpm/WanSlaacCfgRpm.htm. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted packet."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha descubierto una vulnerabilidad de desbordamiento de buffer en TP-Link TL-WR841ND V11, causada por los parámetros dnsserver1 y dnsserver2 en /userRpm/WanSlaacCfgRpm.htm. Esta vulnerabilidad permite a los atacantes ocasionar una denegación de servicio (DoS) mediante un paquete manipulado.\n"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-787"
                            }
                        ]
                    },
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-787"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841nd_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "60843636-698C-4000-84CB-9D441601EDE2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841nd:v11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0B6B17A5-94C4-4B4C-998A-B0B7B7FADB21"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/2664521593/mycve/blob/main/TP-Link/BOF_in_TP-Link_TL-WR841ND-V11_5.pdf",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://github.com/2664521593/mycve/blob/main/TP-Link/BOF_in_TP-Link_TL-WR841ND-V11_5.pdf",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-6151",
                "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                "published": "2025-06-17T01:15:23.313",
                "lastModified": "2025-07-15T19:15:23.380",
                "vulnStatus": "Modified",
                "cveTags": [
                    {
                        "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "unsupported-when-assigned"
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability has been found in \nTP-Link TL-WR940N V4 and TL-WR841N V11. Affected by this issue is some unknown \nfunctionality of the file /userRpm/WanSlaacCfgRpm.htm, which may lead to buffer overflow. The attack may be \nlaunched remotely. This vulnerability only affects products that are no longer \nsupported by the maintainer."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha detectado una vulnerabilidad clasificada como crítica en el TP-Link TL-WR940N V4. Este problema afecta a una funcionalidad desconocida del archivo /userRpm/WanSlaacCfgRpm.htm. La manipulación del argumento dnsserver1 provoca un desbordamiento del búfer. El ataque puede ejecutarse en remoto. Se ha hecho público el exploit y puede que sea utilizado."
                    }
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                "baseScore": 8.2,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "NONE",
                                "vulnIntegrityImpact": "NONE",
                                "vulnAvailabilityImpact": "HIGH",
                                "subConfidentialityImpact": "NONE",
                                "subIntegrityImpact": "NONE",
                                "subAvailabilityImpact": "HIGH",
                                "exploitMaturity": "NOT_DEFINED",
                                "confidentialityRequirement": "NOT_DEFINED",
                                "integrityRequirement": "NOT_DEFINED",
                                "availabilityRequirement": "NOT_DEFINED",
                                "modifiedAttackVector": "NOT_DEFINED",
                                "modifiedAttackComplexity": "NOT_DEFINED",
                                "modifiedAttackRequirements": "NOT_DEFINED",
                                "modifiedPrivilegesRequired": "NOT_DEFINED",
                                "modifiedUserInteraction": "NOT_DEFINED",
                                "modifiedVulnConfidentialityImpact": "NOT_DEFINED",
                                "modifiedVulnIntegrityImpact": "NOT_DEFINED",
                                "modifiedVulnAvailabilityImpact": "NOT_DEFINED",
                                "modifiedSubConfidentialityImpact": "NOT_DEFINED",
                                "modifiedSubIntegrityImpact": "NOT_DEFINED",
                                "modifiedSubAvailabilityImpact": "NOT_DEFINED",
                                "Safety": "NOT_DEFINED",
                                "Automatable": "NOT_DEFINED",
                                "Recovery": "NOT_DEFINED",
                                "valueDensity": "NOT_DEFINED",
                                "vulnerabilityResponseEffort": "NOT_DEFINED",
                                "providerUrgency": "NOT_DEFINED"
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-119"
                            },
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr940n_firmware:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2492A6CA-DFF1-42DC-8800-4A66D8943C33"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr940n:v4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "2537DC7E-8024-45B5-924C-18C9B702DAFC"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/WhereisDoujo/CVE/issues/7",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Exploit",
                            "Issue Tracking",
                            "Third Party Advisory"
                        ]
                    },
                    {
                        "url": "https://vuldb.com/?ctiid.312626",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Permissions Required",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://vuldb.com/?id.312626",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://vuldb.com/?submit.593031",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Third Party Advisory",
                            "VDB Entry"
                        ]
                    },
                    {
                        "url": "https://www.tp-link.com/us/support/faq/4536/",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630"
                    },
                    {
                        "url": "https://github.com/WhereisDoujo/CVE/issues/7",
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "tags": [
                            "Exploit",
                            "Issue Tracking",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-53711",
                "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                "published": "2025-07-29T18:15:30.740",
                "lastModified": "2025-08-01T18:41:18.087",
                "vulnStatus": "Analyzed",
                "cveTags": [
                    {
                        "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "unsupported-when-assigned"
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability has been found in TP-Link TL-WR841N V11. The vulnerability exists in the /userRpm/WlanNetworkRpm.htm file due to missing input parameter validation, which may lead to the buffer overflow to cause a crash of the web service and result in a denial-of-service (DoS) condition. The attack may be launched remotely. This vulnerability only affects products that are no longer supported by the maintainer."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha detectado una vulnerabilidad en TP-Link TL-WR841N V11. La vulnerabilidad se encuentra en el archivo /userRpm/WlanNetworkRpm.htm debido a la falta de validación de los parámetros de entrada, lo que puede provocar un desbordamiento del búfer que provoque un bloqueo del servicio web y una denegación de servicio (DoS). El ataque puede ejecutarse en remoto. Esta vulnerabilidad solo afecta a los productos que ya no reciben soporte del fabricante."
                    }
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                "baseScore": 6.9,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "NONE",
                                "vulnIntegrityImpact": "NONE",
                                "vulnAvailabilityImpact": "HIGH",
                                "subConfidentialityImpact": "NONE",
                                "subIntegrityImpact": "NONE",
                                "subAvailabilityImpact": "NONE",
                                "exploitMaturity": "NOT_DEFINED",
                                "confidentialityRequirement": "NOT_DEFINED",
                                "integrityRequirement": "NOT_DEFINED",
                                "availabilityRequirement": "NOT_DEFINED",
                                "modifiedAttackVector": "NOT_DEFINED",
                                "modifiedAttackComplexity": "NOT_DEFINED",
                                "modifiedAttackRequirements": "NOT_DEFINED",
                                "modifiedPrivilegesRequired": "NOT_DEFINED",
                                "modifiedUserInteraction": "NOT_DEFINED",
                                "modifiedVulnConfidentialityImpact": "NOT_DEFINED",
                                "modifiedVulnIntegrityImpact": "NOT_DEFINED",
                                "modifiedVulnAvailabilityImpact": "NOT_DEFINED",
                                "modifiedSubConfidentialityImpact": "NOT_DEFINED",
                                "modifiedSubIntegrityImpact": "NOT_DEFINED",
                                "modifiedSubAvailabilityImpact": "NOT_DEFINED",
                                "Safety": "NOT_DEFINED",
                                "Automatable": "NOT_DEFINED",
                                "Recovery": "NOT_DEFINED",
                                "valueDensity": "NOT_DEFINED",
                                "vulnerabilityResponseEffort": "NOT_DEFINED",
                                "providerUrgency": "NOT_DEFINED"
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-119"
                            },
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "160325",
                                        "matchCriteriaId": "D7710645-4467-4A8D-BAC0-4B63797E70A2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "508A2761-3DB2-4973-8B9C-22BE876EE987"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.tp-link.com/us/support/faq/4569/",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-53712",
                "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                "published": "2025-07-29T18:15:30.937",
                "lastModified": "2025-08-01T18:43:06.323",
                "vulnStatus": "Analyzed",
                "cveTags": [
                    {
                        "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "unsupported-when-assigned"
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability has been found in TP-Link TL-WR841N V11. The vulnerability exists in the /userRpm/WlanNetworkRpm_AP.htm file due to missing input parameter validation, which may lead to the buffer overflow to cause a crash of the web service and result in a denial-of-service (DoS) condition. The attack may be launched remotely. This vulnerability only affects products that are no longer supported by the maintainer."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha detectado una vulnerabilidad en TP-Link TL-WR841N V11. La vulnerabilidad se encuentra en el archivo /userRpm/WlanNetworkRpm_AP.htm debido a la falta de validación de los parámetros de entrada, lo que puede provocar un desbordamiento del búfer que provoque un bloqueo del servicio web y una denegación de servicio (DoS). El ataque puede ejecutarse en remoto. Esta vulnerabilidad solo afecta a los productos que ya no reciben soporte del fabricante."
                    }
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                "baseScore": 6.9,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "NONE",
                                "vulnIntegrityImpact": "NONE",
                                "vulnAvailabilityImpact": "HIGH",
                                "subConfidentialityImpact": "NONE",
                                "subIntegrityImpact": "NONE",
                                "subAvailabilityImpact": "NONE",
                                "exploitMaturity": "NOT_DEFINED",
                                "confidentialityRequirement": "NOT_DEFINED",
                                "integrityRequirement": "NOT_DEFINED",
                                "availabilityRequirement": "NOT_DEFINED",
                                "modifiedAttackVector": "NOT_DEFINED",
                                "modifiedAttackComplexity": "NOT_DEFINED",
                                "modifiedAttackRequirements": "NOT_DEFINED",
                                "modifiedPrivilegesRequired": "NOT_DEFINED",
                                "modifiedUserInteraction": "NOT_DEFINED",
                                "modifiedVulnConfidentialityImpact": "NOT_DEFINED",
                                "modifiedVulnIntegrityImpact": "NOT_DEFINED",
                                "modifiedVulnAvailabilityImpact": "NOT_DEFINED",
                                "modifiedSubConfidentialityImpact": "NOT_DEFINED",
                                "modifiedSubIntegrityImpact": "NOT_DEFINED",
                                "modifiedSubAvailabilityImpact": "NOT_DEFINED",
                                "Safety": "NOT_DEFINED",
                                "Automatable": "NOT_DEFINED",
                                "Recovery": "NOT_DEFINED",
                                "valueDensity": "NOT_DEFINED",
                                "vulnerabilityResponseEffort": "NOT_DEFINED",
                                "providerUrgency": "NOT_DEFINED"
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-119"
                            },
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "160325",
                                        "matchCriteriaId": "D7710645-4467-4A8D-BAC0-4B63797E70A2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "508A2761-3DB2-4973-8B9C-22BE876EE987"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.tp-link.com/us/support/faq/4569/",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-53713",
                "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                "published": "2025-07-29T18:15:31.113",
                "lastModified": "2025-08-01T18:43:02.853",
                "vulnStatus": "Analyzed",
                "cveTags": [
                    {
                        "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "unsupported-when-assigned"
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability has been found in TP-Link TL-WR841N V11. The vulnerability exists in the /userRpm/WlanNetworkRpm_APC.htm file due to missing input parameter validation, which may lead to the buffer overflow to cause a crash of the web service and result in a denial-of-service (DoS) condition.  The attack may be launched remotely. This vulnerability only affects products that are no longer supported by the maintainer."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha detectado una vulnerabilidad en TP-Link TL-WR841N V11. La vulnerabilidad se encuentra en el archivo /userRpm/WlanNetworkRpm_APC.htm debido a la falta de validación de los parámetros de entrada, lo que puede provocar un desbordamiento del búfer que provoque un bloqueo del servicio web y una denegación de servicio (DoS). El ataque puede ejecutarse en remoto. Esta vulnerabilidad solo afecta a los productos que ya no reciben soporte del fabricante."
                    }
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                "baseScore": 6.9,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "NONE",
                                "vulnIntegrityImpact": "NONE",
                                "vulnAvailabilityImpact": "HIGH",
                                "subConfidentialityImpact": "NONE",
                                "subIntegrityImpact": "NONE",
                                "subAvailabilityImpact": "NONE",
                                "exploitMaturity": "NOT_DEFINED",
                                "confidentialityRequirement": "NOT_DEFINED",
                                "integrityRequirement": "NOT_DEFINED",
                                "availabilityRequirement": "NOT_DEFINED",
                                "modifiedAttackVector": "NOT_DEFINED",
                                "modifiedAttackComplexity": "NOT_DEFINED",
                                "modifiedAttackRequirements": "NOT_DEFINED",
                                "modifiedPrivilegesRequired": "NOT_DEFINED",
                                "modifiedUserInteraction": "NOT_DEFINED",
                                "modifiedVulnConfidentialityImpact": "NOT_DEFINED",
                                "modifiedVulnIntegrityImpact": "NOT_DEFINED",
                                "modifiedVulnAvailabilityImpact": "NOT_DEFINED",
                                "modifiedSubConfidentialityImpact": "NOT_DEFINED",
                                "modifiedSubIntegrityImpact": "NOT_DEFINED",
                                "modifiedSubAvailabilityImpact": "NOT_DEFINED",
                                "Safety": "NOT_DEFINED",
                                "Automatable": "NOT_DEFINED",
                                "Recovery": "NOT_DEFINED",
                                "valueDensity": "NOT_DEFINED",
                                "vulnerabilityResponseEffort": "NOT_DEFINED",
                                "providerUrgency": "NOT_DEFINED"
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-119"
                            },
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "160325",
                                        "matchCriteriaId": "D7710645-4467-4A8D-BAC0-4B63797E70A2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "508A2761-3DB2-4973-8B9C-22BE876EE987"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.tp-link.com/us/support/faq/4569/",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-53714",
                "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                "published": "2025-07-29T18:15:31.277",
                "lastModified": "2025-08-01T18:42:39.883",
                "vulnStatus": "Analyzed",
                "cveTags": [
                    {
                        "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "unsupported-when-assigned"
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability has been found in TP-Link TL-WR841N V11. The vulnerability exists in the /userRpm/WzdWlanSiteSurveyRpm_AP.htm file due to missing input parameter validation, which may lead to the buffer overflow to cause a crash of the web service and result in a denial-of-service (DoS) condition.  The attack may be launched remotely. This vulnerability only affects products that are no longer supported by the maintainer."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha detectado una vulnerabilidad en TP-Link TL-WR841N V11. La vulnerabilidad se encuentra en el archivo /userRpm/WzdWlanSiteSurveyRpm_AP.htm debido a la omisión de la validación de los parámetros de entrada, lo que puede provocar un desbordamiento del búfer que provoque un bloqueo del servicio web y una denegación de servicio (DoS). El ataque puede ejecutarse en remoto. Esta vulnerabilidad solo afecta a los productos que ya no reciben soporte del fabricante."
                    }
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                "baseScore": 6.9,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "NONE",
                                "vulnIntegrityImpact": "NONE",
                                "vulnAvailabilityImpact": "HIGH",
                                "subConfidentialityImpact": "NONE",
                                "subIntegrityImpact": "NONE",
                                "subAvailabilityImpact": "NONE",
                                "exploitMaturity": "NOT_DEFINED",
                                "confidentialityRequirement": "NOT_DEFINED",
                                "integrityRequirement": "NOT_DEFINED",
                                "availabilityRequirement": "NOT_DEFINED",
                                "modifiedAttackVector": "NOT_DEFINED",
                                "modifiedAttackComplexity": "NOT_DEFINED",
                                "modifiedAttackRequirements": "NOT_DEFINED",
                                "modifiedPrivilegesRequired": "NOT_DEFINED",
                                "modifiedUserInteraction": "NOT_DEFINED",
                                "modifiedVulnConfidentialityImpact": "NOT_DEFINED",
                                "modifiedVulnIntegrityImpact": "NOT_DEFINED",
                                "modifiedVulnAvailabilityImpact": "NOT_DEFINED",
                                "modifiedSubConfidentialityImpact": "NOT_DEFINED",
                                "modifiedSubIntegrityImpact": "NOT_DEFINED",
                                "modifiedSubAvailabilityImpact": "NOT_DEFINED",
                                "Safety": "NOT_DEFINED",
                                "Automatable": "NOT_DEFINED",
                                "Recovery": "NOT_DEFINED",
                                "valueDensity": "NOT_DEFINED",
                                "vulnerabilityResponseEffort": "NOT_DEFINED",
                                "providerUrgency": "NOT_DEFINED"
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-119"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "160325",
                                        "matchCriteriaId": "D7710645-4467-4A8D-BAC0-4B63797E70A2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "508A2761-3DB2-4973-8B9C-22BE876EE987"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.tp-link.com/us/support/faq/4569/",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-53715",
                "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                "published": "2025-07-29T18:15:31.430",
                "lastModified": "2025-08-01T18:42:34.247",
                "vulnStatus": "Analyzed",
                "cveTags": [
                    {
                        "sourceIdentifier": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "unsupported-when-assigned"
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability has been found in TP-Link TL-WR841N V11. The vulnerability exists in the /userRpm/Wan6to4TunnelCfgRpm.htm file due to missing input parameter validation, which may lead to the buffer overflow to cause a crash of the web service and result in a denial-of-service (DoS) condition.  The attack may be launched remotely. This vulnerability only affects products that are no longer supported by the maintainer."
                    },
                    {
                        "lang": "es",
                        "value": "Se ha detectado una vulnerabilidad en TP-Link TL-WR841N V11. La vulnerabilidad se encuentra en el archivo /userRpm/Wan6to4TunnelCfgRpm.htm debido a la omisión de la validación de parámetros de entrada, lo que puede provocar un desbordamiento del búfer que provoque un bloqueo del servicio web y una denegación de servicio (DoS). El ataque puede ejecutarse en remoto. Esta vulnerabilidad solo afecta a los productos que ya no reciben soporte del fabricante."
                    }
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                "baseScore": 6.9,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "HIGH",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "NONE",
                                "vulnIntegrityImpact": "NONE",
                                "vulnAvailabilityImpact": "HIGH",
                                "subConfidentialityImpact": "NONE",
                                "subIntegrityImpact": "NONE",
                                "subAvailabilityImpact": "NONE",
                                "exploitMaturity": "NOT_DEFINED",
                                "confidentialityRequirement": "NOT_DEFINED",
                                "integrityRequirement": "NOT_DEFINED",
                                "availabilityRequirement": "NOT_DEFINED",
                                "modifiedAttackVector": "NOT_DEFINED",
                                "modifiedAttackComplexity": "NOT_DEFINED",
                                "modifiedAttackRequirements": "NOT_DEFINED",
                                "modifiedPrivilegesRequired": "NOT_DEFINED",
                                "modifiedUserInteraction": "NOT_DEFINED",
                                "modifiedVulnConfidentialityImpact": "NOT_DEFINED",
                                "modifiedVulnIntegrityImpact": "NOT_DEFINED",
                                "modifiedVulnAvailabilityImpact": "NOT_DEFINED",
                                "modifiedSubConfidentialityImpact": "NOT_DEFINED",
                                "modifiedSubIntegrityImpact": "NOT_DEFINED",
                                "modifiedSubAvailabilityImpact": "NOT_DEFINED",
                                "Safety": "NOT_DEFINED",
                                "Automatable": "NOT_DEFINED",
                                "Recovery": "NOT_DEFINED",
                                "valueDensity": "NOT_DEFINED",
                                "vulnerabilityResponseEffort": "NOT_DEFINED",
                                "providerUrgency": "NOT_DEFINED"
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-119"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:tp-link:tl-wr841n_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "160325",
                                        "matchCriteriaId": "D7710645-4467-4A8D-BAC0-4B63797E70A2"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:tp-link:tl-wr841n:11:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "508A2761-3DB2-4973-8B9C-22BE876EE987"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.tp-link.com/us/support/faq/4569/",
                        "source": "f23511db-6c3e-4e32-a477-6aa17d310630",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        }
    ]
}