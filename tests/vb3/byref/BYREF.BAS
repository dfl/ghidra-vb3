Option Explicit

Global Mark As String
Global Tmp As Variant

Declare Function GetWindowsDirectory Lib "Kernel" (ByVal lpBuffer As String, ByVal nSize As Integer) As Integer

Sub Take_int (x As Integer)
    Tmp = x
End Sub

Sub Hole_int (x As Integer)
End Sub

Sub Pass_int (x As Integer)
    Take_int x
End Sub

Sub Take_long (x As Long)
    Tmp = x
End Sub

Sub Hole_long (x As Long)
End Sub

Sub Pass_long (x As Long)
    Take_long x
End Sub

Sub Take_single (x As Single)
    Tmp = x
End Sub

Sub Hole_single (x As Single)
End Sub

Sub Pass_single (x As Single)
    Take_single x
End Sub

Sub Take_double (x As Double)
    Tmp = x
End Sub

Sub Hole_double (x As Double)
End Sub

Sub Pass_double (x As Double)
    Take_double x
End Sub

Sub Take_currency (x As Currency)
    Tmp = x
End Sub

Sub Hole_currency (x As Currency)
End Sub

Sub Pass_currency (x As Currency)
    Take_currency x
End Sub

Sub Take_string (x As String)
    Tmp = x
End Sub

Sub Hole_string (x As String)
End Sub

Sub Pass_string (x As String)
    Take_string x
End Sub

Sub Take_variant (x As Variant)
    Tmp = x
End Sub

Sub Hole_variant (x As Variant)
End Sub

Sub Pass_variant (x As Variant)
    Take_variant x
End Sub

Sub Case_temp_int ()
    Mark = "CASE temp_int"
    Take_int 1
End Sub

Sub Case_pass_int (x As Integer)
    Mark = "CASE pass_int"
    Take_int x
End Sub

Sub Case_chain_int (x As Integer)
    Mark = "CASE chain_int"
    Pass_int x
End Sub

Sub Case_recv_int (x As Integer)
    Mark = "CASE recv_int"
    Hole_int x
End Sub

Sub Case_skip_int (b As Long, x As Integer)
    Mark = "CASE skip_int"
    Hole_int x
End Sub

Sub Case_skip_byval_int (ByVal b As Integer, x As Integer)
    Mark = "CASE skip_byval_int"
    Hole_int x
End Sub

Sub Case_temp_long ()
    Mark = "CASE temp_long"
    Take_long 100000
End Sub

Sub Case_temp_long_from_int ()
    Mark = "CASE temp_long_from_int"
    Take_long 1
End Sub

Sub Case_pass_long (x As Long)
    Mark = "CASE pass_long"
    Take_long x
End Sub

Sub Case_chain_long (x As Long)
    Mark = "CASE chain_long"
    Pass_long x
End Sub

Sub Case_recv_long (x As Long)
    Mark = "CASE recv_long"
    Hole_long x
End Sub

Sub Case_skip_long (b As Long, x As Long)
    Mark = "CASE skip_long"
    Hole_long x
End Sub

Sub Case_skip_byval_long (ByVal b As Integer, x As Long)
    Mark = "CASE skip_byval_long"
    Hole_long x
End Sub

Sub Case_temp_single ()
    Mark = "CASE temp_single"
    Take_single 1.5!
End Sub

Sub Case_temp_single_from_int ()
    Mark = "CASE temp_single_from_int"
    Take_single 1
End Sub

Sub Case_pass_single (x As Single)
    Mark = "CASE pass_single"
    Take_single x
End Sub

Sub Case_chain_single (x As Single)
    Mark = "CASE chain_single"
    Pass_single x
End Sub

Sub Case_recv_single (x As Single)
    Mark = "CASE recv_single"
    Hole_single x
End Sub

Sub Case_skip_single (b As Long, x As Single)
    Mark = "CASE skip_single"
    Hole_single x
End Sub

Sub Case_skip_byval_single (ByVal b As Integer, x As Single)
    Mark = "CASE skip_byval_single"
    Hole_single x
End Sub

Sub Case_temp_double ()
    Mark = "CASE temp_double"
    Take_double 2.25#
End Sub

Sub Case_temp_double_from_int ()
    Mark = "CASE temp_double_from_int"
    Take_double 1
End Sub

Sub Case_pass_double (x As Double)
    Mark = "CASE pass_double"
    Take_double x
End Sub

Sub Case_chain_double (x As Double)
    Mark = "CASE chain_double"
    Pass_double x
End Sub

Sub Case_recv_double (x As Double)
    Mark = "CASE recv_double"
    Hole_double x
End Sub

Sub Case_skip_double (b As Long, x As Double)
    Mark = "CASE skip_double"
    Hole_double x
End Sub

Sub Case_skip_byval_double (ByVal b As Integer, x As Double)
    Mark = "CASE skip_byval_double"
    Hole_double x
End Sub

Sub Case_temp_currency ()
    Mark = "CASE temp_currency"
    Take_currency 3.75@
End Sub

Sub Case_temp_currency_from_int ()
    Mark = "CASE temp_currency_from_int"
    Take_currency 1
End Sub

Sub Case_pass_currency (x As Currency)
    Mark = "CASE pass_currency"
    Take_currency x
End Sub

Sub Case_chain_currency (x As Currency)
    Mark = "CASE chain_currency"
    Pass_currency x
End Sub

Sub Case_recv_currency (x As Currency)
    Mark = "CASE recv_currency"
    Hole_currency x
End Sub

Sub Case_skip_currency (b As Long, x As Currency)
    Mark = "CASE skip_currency"
    Hole_currency x
End Sub

Sub Case_skip_byval_currency (ByVal b As Integer, x As Currency)
    Mark = "CASE skip_byval_currency"
    Hole_currency x
End Sub

Sub Case_temp_string ()
    Mark = "CASE temp_string"
    Take_string "x"
End Sub

Sub Case_pass_string (x As String)
    Mark = "CASE pass_string"
    Take_string x
End Sub

Sub Case_chain_string (x As String)
    Mark = "CASE chain_string"
    Pass_string x
End Sub

Sub Case_recv_string (x As String)
    Mark = "CASE recv_string"
    Hole_string x
End Sub

Sub Case_skip_string (b As Long, x As String)
    Mark = "CASE skip_string"
    Hole_string x
End Sub

Sub Case_skip_byval_string (ByVal b As Integer, x As String)
    Mark = "CASE skip_byval_string"
    Hole_string x
End Sub

Sub Case_temp_variant ()
    Mark = "CASE temp_variant"
    Take_variant 1
End Sub

Sub Case_pass_variant (x As Variant)
    Mark = "CASE pass_variant"
    Take_variant x
End Sub

Sub Case_chain_variant (x As Variant)
    Mark = "CASE chain_variant"
    Pass_variant x
End Sub

Sub Case_recv_variant (x As Variant)
    Mark = "CASE recv_variant"
    Hole_variant x
End Sub

Sub Case_skip_variant (b As Long, x As Variant)
    Mark = "CASE skip_variant"
    Hole_variant x
End Sub

Sub Case_skip_byval_variant (ByVal b As Integer, x As Variant)
    Mark = "CASE skip_byval_variant"
    Hole_variant x
End Sub

Sub Case_chdrive_string (s As String)
    Mark = "CASE chdrive_string"
    ChDrive s
End Sub

Sub Case_kill_string (s As String)
    Mark = "CASE kill_string"
    Kill s
End Sub

Sub Case_byval_string (s As String)
    Mark = "CASE byval_string"
    Tmp = GetWindowsDirectory(s, 10)
End Sub

Sub Main ()
    Dim a_int As Integer
    a_int = 1
    Case_recv_int a_int
    Case_skip_int 1, 1
    Case_skip_byval_int 1, 1
    Dim a_long As Long
    a_long = 100000
    Case_recv_long a_long
    Case_skip_long 1, 100000
    Case_skip_byval_long 1, 100000
    Dim a_single As Single
    a_single = 1.5!
    Case_recv_single a_single
    Case_skip_single 1, 1.5!
    Case_skip_byval_single 1, 1.5!
    Dim a_double As Double
    a_double = 2.25#
    Case_recv_double a_double
    Case_skip_double 1, 2.25#
    Case_skip_byval_double 1, 2.25#
    Dim a_currency As Currency
    a_currency = 3.75@
    Case_recv_currency a_currency
    Case_skip_currency 1, 3.75@
    Case_skip_byval_currency 1, 3.75@
    Dim a_string As String
    a_string = "x"
    Case_recv_string a_string
    Case_skip_string 1, "x"
    Case_skip_byval_string 1, "x"
    Dim a_variant As Variant
    a_variant = 1
    Case_recv_variant a_variant
    Case_skip_variant 1, 1
    Case_skip_byval_variant 1, 1
End Sub

