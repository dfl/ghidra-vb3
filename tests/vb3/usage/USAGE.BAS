Option Explicit

Global Mark As String
Global Tmp As Variant
Global G_int() As Integer
Global G_long() As Long
Global G_single() As Single
Global G_double() As Double
Global G_currency() As Currency
Global G_string() As String
Global G_variant() As Variant
Dim M_int() As Integer
Dim M_long() As Long
Dim M_single() As Single
Dim M_double() As Double
Dim M_currency() As Currency
Dim M_string() As String
Dim M_variant() As Variant
Dim R_int() As Integer
Dim R_long() As Long
Dim R_single() As Single
Dim R_double() As Double
Dim R_currency() As Currency
Dim R_string() As String
Dim R_variant() As Variant

Sub Take_int (x As Integer)
    Tmp = x
End Sub

Sub Take_long (x As Long)
    Tmp = x
End Sub

Sub Take_single (x As Single)
    Tmp = x
End Sub

Sub Take_double (x As Double)
    Tmp = x
End Sub

Sub Take_currency (x As Currency)
    Tmp = x
End Sub

Sub Take_string (x As String)
    Tmp = x
End Sub

Sub Take_variant (x As Variant)
    Tmp = x
End Sub

Sub Case_for_int ()
    Mark = "CASE for_int"
    Dim i As Integer
    For i = 1 To 3
    Next i
End Sub

Sub Case_elem_local_int ()
    Mark = "CASE elem_local_int"
    Dim a() As Integer
    ReDim a(1 To 3)
    a(1) = 1
    Tmp = a(2)
End Sub

Sub Case_elem_module_int ()
    Mark = "CASE elem_module_int"
    ReDim M_int(1 To 3)
    M_int(1) = 1
    Tmp = M_int(2)
End Sub

Sub Case_elem_global_int ()
    Mark = "CASE elem_global_int"
    ReDim G_int(1 To 3)
    G_int(1) = 1
    Tmp = G_int(2)
End Sub

Sub Case_elemref_int ()
    Mark = "CASE elemref_int"
    ReDim R_int(1 To 3)
    Take_int R_int(1)
End Sub

Sub Case_cmp_int (x As Integer)
    Mark = "CASE cmp_int"
    If x = 1 Then Tmp = 0
End Sub

Sub Case_for_long ()
    Mark = "CASE for_long"
    Dim i As Long
    For i = 1 To 3
    Next i
End Sub

Sub Case_elem_local_long ()
    Mark = "CASE elem_local_long"
    Dim a() As Long
    ReDim a(1 To 3)
    a(1) = 100000
    Tmp = a(2)
End Sub

Sub Case_elem_module_long ()
    Mark = "CASE elem_module_long"
    ReDim M_long(1 To 3)
    M_long(1) = 100000
    Tmp = M_long(2)
End Sub

Sub Case_elem_global_long ()
    Mark = "CASE elem_global_long"
    ReDim G_long(1 To 3)
    G_long(1) = 100000
    Tmp = G_long(2)
End Sub

Sub Case_elemref_long ()
    Mark = "CASE elemref_long"
    ReDim R_long(1 To 3)
    Take_long R_long(1)
End Sub

Sub Case_cmp_long (x As Long)
    Mark = "CASE cmp_long"
    If x = 1 Then Tmp = 0
End Sub

Sub Case_for_single ()
    Mark = "CASE for_single"
    Dim i As Single
    For i = 1 To 3
    Next i
End Sub

Sub Case_elem_local_single ()
    Mark = "CASE elem_local_single"
    Dim a() As Single
    ReDim a(1 To 3)
    a(1) = 1.5!
    Tmp = a(2)
End Sub

Sub Case_elem_module_single ()
    Mark = "CASE elem_module_single"
    ReDim M_single(1 To 3)
    M_single(1) = 1.5!
    Tmp = M_single(2)
End Sub

Sub Case_elem_global_single ()
    Mark = "CASE elem_global_single"
    ReDim G_single(1 To 3)
    G_single(1) = 1.5!
    Tmp = G_single(2)
End Sub

Sub Case_elemref_single ()
    Mark = "CASE elemref_single"
    ReDim R_single(1 To 3)
    Take_single R_single(1)
End Sub

Sub Case_cmp_single (x As Single)
    Mark = "CASE cmp_single"
    If x = 1 Then Tmp = 0
End Sub

Sub Case_for_double ()
    Mark = "CASE for_double"
    Dim i As Double
    For i = 1 To 3
    Next i
End Sub

Sub Case_elem_local_double ()
    Mark = "CASE elem_local_double"
    Dim a() As Double
    ReDim a(1 To 3)
    a(1) = 2.25#
    Tmp = a(2)
End Sub

Sub Case_elem_module_double ()
    Mark = "CASE elem_module_double"
    ReDim M_double(1 To 3)
    M_double(1) = 2.25#
    Tmp = M_double(2)
End Sub

Sub Case_elem_global_double ()
    Mark = "CASE elem_global_double"
    ReDim G_double(1 To 3)
    G_double(1) = 2.25#
    Tmp = G_double(2)
End Sub

Sub Case_elemref_double ()
    Mark = "CASE elemref_double"
    ReDim R_double(1 To 3)
    Take_double R_double(1)
End Sub

Sub Case_cmp_double (x As Double)
    Mark = "CASE cmp_double"
    If x = 1 Then Tmp = 0
End Sub

Sub Case_for_currency ()
    Mark = "CASE for_currency"
    Dim i As Currency
    For i = 1 To 3
    Next i
End Sub

Sub Case_elem_local_currency ()
    Mark = "CASE elem_local_currency"
    Dim a() As Currency
    ReDim a(1 To 3)
    a(1) = 3.75@
    Tmp = a(2)
End Sub

Sub Case_elem_module_currency ()
    Mark = "CASE elem_module_currency"
    ReDim M_currency(1 To 3)
    M_currency(1) = 3.75@
    Tmp = M_currency(2)
End Sub

Sub Case_elem_global_currency ()
    Mark = "CASE elem_global_currency"
    ReDim G_currency(1 To 3)
    G_currency(1) = 3.75@
    Tmp = G_currency(2)
End Sub

Sub Case_elemref_currency ()
    Mark = "CASE elemref_currency"
    ReDim R_currency(1 To 3)
    Take_currency R_currency(1)
End Sub

Sub Case_cmp_currency (x As Currency)
    Mark = "CASE cmp_currency"
    If x = 1 Then Tmp = 0
End Sub

Sub Case_elem_local_string ()
    Mark = "CASE elem_local_string"
    Dim a() As String
    ReDim a(1 To 3)
    a(1) = "x"
    Tmp = a(2)
End Sub

Sub Case_elem_module_string ()
    Mark = "CASE elem_module_string"
    ReDim M_string(1 To 3)
    M_string(1) = "x"
    Tmp = M_string(2)
End Sub

Sub Case_elem_global_string ()
    Mark = "CASE elem_global_string"
    ReDim G_string(1 To 3)
    G_string(1) = "x"
    Tmp = G_string(2)
End Sub

Sub Case_elemref_string ()
    Mark = "CASE elemref_string"
    ReDim R_string(1 To 3)
    Take_string R_string(1)
End Sub

Sub Case_cmp_string (x As String)
    Mark = "CASE cmp_string"
    If x = "1" Then Tmp = 0
End Sub

Sub Case_elem_local_variant ()
    Mark = "CASE elem_local_variant"
    Dim a() As Variant
    ReDim a(1 To 3)
    a(1) = 1
    Tmp = a(2)
End Sub

Sub Case_elem_module_variant ()
    Mark = "CASE elem_module_variant"
    ReDim M_variant(1 To 3)
    M_variant(1) = 1
    Tmp = M_variant(2)
End Sub

Sub Case_elem_global_variant ()
    Mark = "CASE elem_global_variant"
    ReDim G_variant(1 To 3)
    G_variant(1) = 1
    Tmp = G_variant(2)
End Sub

Sub Case_elemref_variant ()
    Mark = "CASE elemref_variant"
    ReDim R_variant(1 To 3)
    Take_variant R_variant(1)
End Sub

Sub Case_cmp_variant (x As Variant)
    Mark = "CASE cmp_variant"
    If x = 1 Then Tmp = 0
End Sub

Sub Main ()
    Case_for_int
    Case_for_long
    Case_for_single
    Case_for_double
    Case_for_currency
End Sub

