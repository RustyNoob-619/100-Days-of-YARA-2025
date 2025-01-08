rule Script_Python_Exploit_CVE_2024_49113
{
  meta:
    author = "RustyNoob619"
    description = "Detects expolit script (relies on exploit_server py) for the CVE-2024-49113 also known as LDAPNightmare"
    filehash = "1b062243ad5c9398ef05a038c3a1d5a288010b517658d3690d8c20b57842e453" 
    reference = "https://www.safebreach.com/blog/ldapnightmare-safebreach-labs-publishes-first-proof-of-concept-exploit-for-cve-2024-49113/"
   
  strings:
    $imprt1 = "DsrGetDcNameEx2" fullword
    $imprt2 = "run_exploit_server" fullword
    $ldap1 = "LDAP server"
    $ldap2 = "start_ldap_server"
    $rpc1 = "rpc_call"
    $rpc2 = "RPC"
    $params1 = "--port"
    $params2 = "--listen-port"
    $params3 = "--domain-name"
    $params4 = "--account"
    $params5 = "--site-name"
    $dfltprt = "49664"

  condition:
    File_Format_Script_Python // From Day3 ruleset
    and all of ($imprt*)
    and any of ($ldap*)
    and any of ($rpc*)
    and 3 of ($params*)
    and $dfltprt
    and filesize < 10KB

}

