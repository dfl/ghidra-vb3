Option Explicit

Global Mark As String
Global Tmp As Variant
Global G_Long As Long

Dim M_int As Integer
Dim M_long As Long
Dim M_single As Single
Dim M_double As Double
Dim M_currency As Currency
Dim M_variant As Variant
Dim M_string As String

Sub TakeString (s As String)
    Tmp = s
End Sub

Sub Main ()
    Case_int_local
    Dim a_int As Integer
    a_int = 1
    Case_int_param a_int
    Case_int_byval a_int
    Case_int_static
    Case_int_module
    Case_int_array
    Case_long_local
    Dim a_long As Long
    a_long = 100000
    Case_long_param a_long
    Case_long_byval a_long
    Case_long_static
    Case_long_module
    Case_long_array
    Case_single_local
    Dim a_single As Single
    a_single = 1.5
    Case_single_param a_single
    Case_single_byval a_single
    Case_single_static
    Case_single_module
    Case_single_array
    Case_double_local
    Dim a_double As Double
    a_double = 2.25
    Case_double_param a_double
    Case_double_byval a_double
    Case_double_static
    Case_double_module
    Case_double_array
    Case_currency_local
    Dim a_currency As Currency
    a_currency = 3.75
    Case_currency_param a_currency
    Case_currency_byval a_currency
    Case_currency_static
    Case_currency_module
    Case_currency_array
    Case_variant_local
    Dim a_variant As Variant
    a_variant = 4
    Case_variant_param a_variant
    Case_variant_byval a_variant
    Case_variant_static
    Case_variant_module
    Case_variant_array
    Case_string_local
    Dim a_string As String
    a_string = "s"
    Case_string_param a_string
    Case_string_byval a_string
    Case_string_static
    Case_string_module
    Case_string_array
    Case_long_global
    Case_double_redim
    Case_form_object
    Case_string_len_only
    Case_string_passed_byref
    Case_long_compare_literal
    Case_int_static_array
    Case_long_static_array
    Case_single_static_array
    Case_double_static_array
    Case_currency_static_array
    Case_variant_static_array
    Case_string_static_array
End Sub

Sub Case_int_local ()
    Mark = "CASE int_local"
    Dim v As Integer
    v = 1
    Tmp = v
End Sub

Sub Case_int_param (v As Integer)
    Mark = "CASE int_param"
    Tmp = v
End Sub

Sub Case_int_byval (ByVal v As Integer)
    Mark = "CASE int_byval"
    Tmp = v
End Sub

Sub Case_int_static ()
    Mark = "CASE int_static"
    Static v As Integer
    v = 1
    Tmp = v
End Sub

Sub Case_int_module ()
    Mark = "CASE int_module"
    M_int = 1
    Tmp = M_int
End Sub

Sub Case_int_array ()
    Mark = "CASE int_array"
    ReDim v(1 To 3) As Integer
    v(2) = 1
    Tmp = v(2)
End Sub

Sub Case_long_local ()
    Mark = "CASE long_local"
    Dim v As Long
    v = 100000
    Tmp = v
End Sub

Sub Case_long_param (v As Long)
    Mark = "CASE long_param"
    Tmp = v
End Sub

Sub Case_long_byval (ByVal v As Long)
    Mark = "CASE long_byval"
    Tmp = v
End Sub

Sub Case_long_static ()
    Mark = "CASE long_static"
    Static v As Long
    v = 100000
    Tmp = v
End Sub

Sub Case_long_module ()
    Mark = "CASE long_module"
    M_long = 100000
    Tmp = M_long
End Sub

Sub Case_long_array ()
    Mark = "CASE long_array"
    ReDim v(1 To 3) As Long
    v(2) = 100000
    Tmp = v(2)
End Sub

Sub Case_single_local ()
    Mark = "CASE single_local"
    Dim v As Single
    v = 1.5
    Tmp = v
End Sub

Sub Case_single_param (v As Single)
    Mark = "CASE single_param"
    Tmp = v
End Sub

Sub Case_single_byval (ByVal v As Single)
    Mark = "CASE single_byval"
    Tmp = v
End Sub

Sub Case_single_static ()
    Mark = "CASE single_static"
    Static v As Single
    v = 1.5
    Tmp = v
End Sub

Sub Case_single_module ()
    Mark = "CASE single_module"
    M_single = 1.5
    Tmp = M_single
End Sub

Sub Case_single_array ()
    Mark = "CASE single_array"
    ReDim v(1 To 3) As Single
    v(2) = 1.5
    Tmp = v(2)
End Sub

Sub Case_double_local ()
    Mark = "CASE double_local"
    Dim v As Double
    v = 2.25
    Tmp = v
End Sub

Sub Case_double_param (v As Double)
    Mark = "CASE double_param"
    Tmp = v
End Sub

Sub Case_double_byval (ByVal v As Double)
    Mark = "CASE double_byval"
    Tmp = v
End Sub

Sub Case_double_static ()
    Mark = "CASE double_static"
    Static v As Double
    v = 2.25
    Tmp = v
End Sub

Sub Case_double_module ()
    Mark = "CASE double_module"
    M_double = 2.25
    Tmp = M_double
End Sub

Sub Case_double_array ()
    Mark = "CASE double_array"
    ReDim v(1 To 3) As Double
    v(2) = 2.25
    Tmp = v(2)
End Sub

Sub Case_currency_local ()
    Mark = "CASE currency_local"
    Dim v As Currency
    v = 3.75
    Tmp = v
End Sub

Sub Case_currency_param (v As Currency)
    Mark = "CASE currency_param"
    Tmp = v
End Sub

Sub Case_currency_byval (ByVal v As Currency)
    Mark = "CASE currency_byval"
    Tmp = v
End Sub

Sub Case_currency_static ()
    Mark = "CASE currency_static"
    Static v As Currency
    v = 3.75
    Tmp = v
End Sub

Sub Case_currency_module ()
    Mark = "CASE currency_module"
    M_currency = 3.75
    Tmp = M_currency
End Sub

Sub Case_currency_array ()
    Mark = "CASE currency_array"
    ReDim v(1 To 3) As Currency
    v(2) = 3.75
    Tmp = v(2)
End Sub

Sub Case_variant_local ()
    Mark = "CASE variant_local"
    Dim v As Variant
    v = 4
    Tmp = v
End Sub

Sub Case_variant_param (v As Variant)
    Mark = "CASE variant_param"
    Tmp = v
End Sub

Sub Case_variant_byval (ByVal v As Variant)
    Mark = "CASE variant_byval"
    Tmp = v
End Sub

Sub Case_variant_static ()
    Mark = "CASE variant_static"
    Static v As Variant
    v = 4
    Tmp = v
End Sub

Sub Case_variant_module ()
    Mark = "CASE variant_module"
    M_variant = 4
    Tmp = M_variant
End Sub

Sub Case_variant_array ()
    Mark = "CASE variant_array"
    ReDim v(1 To 3) As Variant
    v(2) = 4
    Tmp = v(2)
End Sub

Sub Case_string_local ()
    Mark = "CASE string_local"
    Dim v As String
    v = "s"
    Tmp = v
End Sub

Sub Case_string_param (v As String)
    Mark = "CASE string_param"
    Tmp = v
End Sub

Sub Case_string_byval (ByVal v As String)
    Mark = "CASE string_byval"
    Tmp = v
End Sub

Sub Case_string_static ()
    Mark = "CASE string_static"
    Static v As String
    v = "s"
    Tmp = v
End Sub

Sub Case_string_module ()
    Mark = "CASE string_module"
    M_string = "s"
    Tmp = M_string
End Sub

Sub Case_string_array ()
    Mark = "CASE string_array"
    ReDim v(1 To 3) As String
    v(2) = "s"
    Tmp = v(2)
End Sub

Sub Case_long_global ()
    Mark = "CASE long_global"
    G_Long = 70000
    Tmp = G_Long
End Sub

Sub Case_double_redim ()
    Mark = "CASE double_redim"
    Dim v() As Double
    ReDim v(1 To 4) As Double
    v(1) = 1.5
    Tmp = v(1)
End Sub

Sub Case_form_object ()
    Mark = "CASE form_object"
    Dim f As Form
    Set f = Form1
    f.Caption = "x"
End Sub

Sub Case_string_len_only ()
    Mark = "CASE string_len_only"
    Dim v As String
    Tmp = Len(v)
End Sub

Sub Case_string_passed_byref ()
    Mark = "CASE string_passed_byref"
    Dim v As String
    TakeString v
End Sub

Sub Case_long_compare_literal ()
    Mark = "CASE long_compare_literal"
    Dim v As Long
    If v > 100000 Then Tmp = 1
End Sub

Sub Case_int_static_array ()
    Mark = "CASE int_static_array"
    Static v(1 To 3) As Integer
    v(2) = 1
    Tmp = v(2)
End Sub

Sub Case_long_static_array ()
    Mark = "CASE long_static_array"
    Static v(1 To 3) As Long
    v(2) = 100000
    Tmp = v(2)
End Sub

Sub Case_single_static_array ()
    Mark = "CASE single_static_array"
    Static v(1 To 3) As Single
    v(2) = 1.5
    Tmp = v(2)
End Sub

Sub Case_double_static_array ()
    Mark = "CASE double_static_array"
    Static v(1 To 3) As Double
    v(2) = 2.25
    Tmp = v(2)
End Sub

Sub Case_currency_static_array ()
    Mark = "CASE currency_static_array"
    Static v(1 To 3) As Currency
    v(2) = 3.75
    Tmp = v(2)
End Sub

Sub Case_variant_static_array ()
    Mark = "CASE variant_static_array"
    Static v(1 To 3) As Variant
    v(2) = 4
    Tmp = v(2)
End Sub

Sub Case_string_static_array ()
    Mark = "CASE string_static_array"
    Static v(1 To 3) As String
    v(2) = "s"
    Tmp = v(2)
End Sub
