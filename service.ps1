#
# MIT License
#
# Copyright (c) 2019 Rokas Kupstys
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
param([switch]$remove, [String]$path, [String]$name='vr', [String]$group='netsvcs')
$path = $(Resolve-Path $path)

$svclist = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost' -name $group).$group
$svclist = $svclist|where{$_ -ne $name }
if (!$remove) {
    $svclist += $name
}
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost' -name $group -value $svclist
sc.exe delete $name

if (!$remove) {
    sc.exe create $name binPath= "%systemroot%\system32\svchost.exe -k $group" type= share
    New-Item -Path HKLM:\SYSTEM\CurrentControlSet\services\$name -name Parameters
    New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\services\$name\Parameters -propertyType ExpandString -name ServiceDll -value $path
}
