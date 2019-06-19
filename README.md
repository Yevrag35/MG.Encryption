# StringCertProtection - MG.Encryption

[![version](https://img.shields.io/powershellgallery/v/StringCertProtection.svg)](https://www.powershellgallery.com/packages/StringCertProtection)
[![downloads](https://img.shields.io/powershellgallery/dt/StringCertProtection.svg?label=downloads)](https://www.powershellgallery.com/stats/packages/StringCertProtection?groupby=Version)

This module provides cmdlets to secure plain-text strings using certificate-based encryption.

There are 5 commands included in the module:

1. New-StringCertificate
1. Protect-String
1. Protect-StringToRegistry
1. Unprotect-String
1. Unprotect-StringFromRegistry

The big thing to note is that the "-Securable" object parameter can accept the following inputs:

* String
* Int32
* byte[]
* SecureString
* PSCredential
* NetworkCredential
* SqlCredential

By allowing all of these types through one parameter, it makes writing scripts easier without having to accommodate the parameter.
