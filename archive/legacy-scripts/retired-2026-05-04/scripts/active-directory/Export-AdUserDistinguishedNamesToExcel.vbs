' CreateUserList3.vbs
' VBScript program to create a Microsoft Excel spreadsheet documenting
' all users in the domain.
'
' ----------------------------------------------------------------------
' Copyright (c) 2002 Richard L. Mueller
' Hilltop Lab web site - http://www.rlmueller.net
' Version 1.0 - November 12, 2002
' Version 1.1 - February 19, 2003 - Standardize Hungarian notation.
' This program enumerates all users in the domain and writes each user's
' LDAP DistinguishedName to a Microsoft Excel spreadsheet.
'
' You have a royalty-free right to use, modify, reproduce, and
' distribute this script file in any way you find useful, provided that
' you agree that the copyright owner above has no warranty, obligations,
' or liability for such use.

Option Explicit

Dim strExcelPath, objConnection, objCommand, objRootDSE, strDNSDomain
Dim strFilter, strQuery, objRecordSet, strDN, objExcel, objSheet, k

' Check for required arguments.
If Wscript.Arguments.Count < 1 Then
  Wscript.Echo "Arguments <FileName> required. For example:" & vbCrLf _
    & "cscript CreateUserList3.vbs c:\MyFolder\UserList3.xls"
  Wscript.Quit(0)
End If

' Spreadsheet file to be created.
strExcelPath = Wscript.Arguments(0)

' Bind to Excel object.
Set objExcel = CreateObject("Excel.Application")
objExcel.Workbooks.Add

' Bind to worksheet.
Set objSheet = objExcel.ActiveWorkbook.Worksheets(1)
objSheet.Name = "Domain User"
objSheet.Cells(1, 1).Value = "User Distinguished Name"

' Use ADO to search the domain for all users.
Set objConnection = CreateObject("ADODB.Connection")
Set objCommand = CreateObject("ADODB.Command")
objConnection.Provider = "ADsDSOOBject"
objConnection.Open "Active Directory Provider"
Set objCommand.ActiveConnection = objConnection

' Determine the DNS domain from the RootDSE object.
Set objRootDSE = GetObject("LDAP://RootDSE")
strDNSDomain = objRootDSE.Get("defaultNamingContext")
strFilter = "(&(objectCategory=person)(objectClass=user))"
strQuery = "<LDAP://" & strDNSDomain & ">;" & strFilter _
  & ";distinguishedName;subtree"

objCommand.CommandText = strQuery
objCommand.Properties("Page Size") = 100
objCommand.Properties("Timeout") = 30
objCommand.Properties("Cache Results") = False

' Enumerate all users. Write each user's Distinguished Name to the
' spreadsheet.
k = 2
Set objRecordSet = objCommand.Execute
Do Until objRecordSet.EOF
  strDN = objRecordSet.Fields("distinguishedName")
  objSheet.Cells(k, 1).Value = strDN
  k = k + 1
  objRecordSet.MoveNext
Loop

' Format the spreadsheet.
objSheet.Range("A1:A1").Font.Bold = True
objSheet.Select
objExcel.Columns(1).ColumnWidth = 80

' Save the spreadsheet.
objExcel.ActiveWorkbook.SaveAs strExcelPath
objExcel.ActiveWorkbook.Close

' Quit Excel.
objExcel.Application.Quit

' Clean up.
objConnection.Close
Set objConnection = Nothing
Set objCommand = Nothing
Set objRootDSE = Nothing
Set objRecordSet = Nothing
Set objSheet = Nothing
Set objExcel = Nothing

Wscript.Echo "Done"
