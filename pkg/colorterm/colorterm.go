package colorterm

import "fmt"

type color string

const (
	ColorNone color = "\x1b[0m"

	ColorRed     color = "\x1b[31m"
	ColorGreen   color = "\x1b[32m"
	ColorYellow  color = "\x1b[33m"
	ColorBlue    color = "\x1b[34m"
	ColorMagenta color = "\x1b[35m"

	ColorPanic   color = "\x1b[38;5;124m"
	ColorError   color = "\x1b[38;5;124m"
	ColorWarning color = "\x1b[38;5;208m"
	ColorInfo    color = "\x1b[38;5;33m"
	ColorDebug   color = "\x1b[38;5;153m"
	ColorSuccess color = "\x1b[38;5;34m"
)

var ct = New()

type CT struct{}

func New() *CT {
	return &CT{}
}

func (ct *CT) Sprintf(c color, format string, a ...any) string {
	return fmt.Sprintf("%s%s%s", c, fmt.Sprintf(format, a...), ColorNone)
}

func (ct *CT) Sprint(c color, a ...any) string {
	return fmt.Sprintf("%s%s%s", c, fmt.Sprint(a...), ColorNone)
}

func (ct *CT) Print(c color, a ...any) *CT {
	return ct.Println(c, a...)
}

func (ct *CT) Printf(c color, format string, a ...any) *CT {
	fmt.Println(ct.Sprintf(c, format, a...))
	return ct
}

func (ct *CT) Println(c color, a ...any) *CT {
	fmt.Print(c)
	fmt.Println(a...)
	fmt.Print(ColorNone)
	return ct
}

func (ct *CT) None(a ...any) *CT {
	ct.Print(ColorNone, a...)
	return ct
}

func (ct *CT) Nonef(format string, a ...any) *CT {
	ct.Printf(ColorNone, format, a...)
	return ct
}

func (ct *CT) Red(a ...any) *CT {
	ct.Print(ColorRed, a...)
	return ct
}

func (ct *CT) Redf(format string, a ...any) *CT {
	ct.Printf(ColorRed, format, a...)
	return ct
}

func (ct *CT) Green(a ...any) *CT {
	ct.Print(ColorGreen, a...)
	return ct
}

func (ct *CT) Greenf(format string, a ...any) *CT {
	ct.Printf(ColorGreen, format, a...)
	return ct
}

func (ct *CT) Yellow(a ...any) *CT {
	ct.Print(ColorYellow, a...)
	return ct
}

func (ct *CT) Yellowf(format string, a ...any) *CT {
	ct.Printf(ColorYellow, format, a...)
	return ct
}

func (ct *CT) Blue(a ...any) *CT {
	ct.Print(ColorBlue, a...)
	return ct
}

func (ct *CT) Bluef(format string, a ...any) *CT {
	ct.Printf(ColorBlue, format, a...)
	return ct
}

func (ct *CT) Magenta(a ...any) *CT {
	ct.Print(ColorMagenta, a...)
	return ct
}

func (ct *CT) Magentaf(format string, a ...any) *CT {
	ct.Printf(ColorMagenta, format, a...)
	return ct
}

func (ct *CT) Panic(a ...any) *CT {
	ct.Print(ColorPanic, a...)
	return ct
}

func (ct *CT) Panicf(format string, a ...any) *CT {
	ct.Printf(ColorPanic, format, a...)
	return ct
}

func (ct *CT) Error(a ...any) *CT {
	ct.Print(ColorError, a...)
	return ct
}

func (ct *CT) Errorf(format string, a ...any) *CT {
	ct.Printf(ColorError, format, a...)
	return ct
}

func (ct *CT) Warning(a ...any) *CT {
	ct.Print(ColorWarning, a...)
	return ct
}

func (ct *CT) Warningf(format string, a ...any) *CT {
	ct.Printf(ColorWarning, format, a...)
	return ct
}

func (ct *CT) Info(a ...any) *CT {
	ct.Print(ColorInfo, a...)
	return ct
}

func (ct *CT) Infof(format string, a ...any) *CT {
	ct.Printf(ColorInfo, format, a...)
	return ct
}

func (ct *CT) Debug(a ...any) *CT {
	ct.Print(ColorDebug, a...)
	return ct
}

func (ct *CT) Debugf(format string, a ...any) *CT {
	ct.Printf(ColorDebug, format, a...)
	return ct
}

func (ct *CT) Success(a ...any) *CT {
	ct.Print(ColorSuccess, a...)
	return ct
}

func (ct *CT) Successf(format string, a ...any) *CT {
	ct.Printf(ColorSuccess, format, a...)
	return ct
}

func (ct *CT) NewLine() *CT {
	fmt.Println()
	return ct
}

// ---------------------

func Sprintf(c color, format string, a ...any) string {
	return ct.Sprintf(c, format, a...)
}

func Sprint(c color, a ...any) string {
	return ct.Sprint(c, a...)
}

func Print(c color, a ...any) *CT {
	return ct.Print(c, a...)
}

func Printf(c color, format string, a ...any) *CT {
	return ct.Printf(c, format, a...)
}

func Println(c color, a ...any) *CT {
	return ct.Println(c, a...)
}

func None(a ...any) *CT {
	return ct.None(a...)
}

func Nonef(format string, a ...any) *CT {
	return ct.Nonef(format, a...)
}

func Red(a ...any) *CT {
	return ct.Red(a...)
}

func Redf(format string, a ...any) *CT {
	return ct.Redf(format, a...)
}

func Green(a ...any) *CT {
	return ct.Green(a...)
}

func Greenf(format string, a ...any) *CT {
	return ct.Greenf(format, a...)
}

func Yellow(a ...any) *CT {
	return ct.Yellow(a...)
}

func Yellowf(format string, a ...any) *CT {
	return ct.Yellowf(format, a...)
}

func Blue(a ...any) *CT {
	return ct.Blue(a...)
}

func Bluef(format string, a ...any) *CT {
	return ct.Bluef(format, a...)
}

func Magenta(a ...any) *CT {
	return ct.Magenta(a...)
}

func Magentaf(format string, a ...any) *CT {
	return ct.Magentaf(format, a...)
}

func Panic(a ...any) *CT {
	return ct.Panic(a...)
}

func Panicf(format string, a ...any) *CT {
	return ct.Panicf(format, a...)
}

func Error(a ...any) *CT {
	return ct.Error(a...)
}

func Errorf(format string, a ...any) *CT {
	return ct.Errorf(format, a...)
}

func Warning(a ...any) *CT {
	return ct.Warning(a...)
}

func Warningf(format string, a ...any) *CT {
	return ct.Warningf(format, a...)
}

func Info(a ...any) *CT {
	return ct.Info(a...)
}

func Infof(format string, a ...any) *CT {
	return ct.Infof(format, a...)
}

func Debug(a ...any) *CT {
	return ct.Debug(a...)
}

func Debugf(format string, a ...any) *CT {
	return ct.Debugf(format, a...)
}

func Success(a ...any) *CT {
	return ct.Success(a...)
}

func Successf(format string, a ...any) *CT {
	return ct.Successf(format, a...)
}
