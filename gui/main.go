package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/byteness/keyring"
	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/log"
	"github.com/majd/ipatool/v2/pkg/util"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"github.com/rs/zerolog"
)

const (
	configDirectoryName = ".ipatool"
	cookieJarFileName   = "cookies"
	keychainServiceName = "ipatool-auth.service"
)

var lang = "system"

func detectSystemLang() string {
	langID, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage").Call()
	switch uint16(langID) {
	case 0x0409, 0x0809, 0x0c09, 0x1009, 0x1409, 0x1809, 0x1c09, 0x2009, 0x2409, 0x2809, 0x2c09, 0x3009, 0x3409:
		return "en"
	}
	return "zh"
}

func effectiveLang() string {
	if lang == "system" { return detectSystemLang() }
	return lang
}

var tr = map[string]map[string]string{
	"keychain":      {"zh": "\u5bc6\u94a5\u94fe", "en": "Keychain"},
	"keychain_pw":   {"zh": "\u5bc6\u94a5\u94fe\u5bc6\u7801:", "en": "Passphrase:"},
	"unlock":        {"zh": "\u89e3\u9501\u5bc6\u94a5\u94fe", "en": "Unlock Keychain"},
	"unlock_ok":     {"zh": "\u5bc6\u94a5\u94fe\u5df2\u89e3\u9501", "en": "Keychain unlocked"},
	"unlocked":      {"zh": "\u5bc6\u94a5\u94fe\u5df2\u89e3\u9501\u3002", "en": "Keychain unlocked."},
	"login_title":   {"zh": "\u767b\u5f55 App Store", "en": "Login to App Store"},
	"email":         {"zh": "Apple ID \u90ae\u7bb1:", "en": "Apple ID Email:"},
	"password":      {"zh": "\u5bc6\u7801:", "en": "Password:"},
	"2fa":           {"zh": "\u4e24\u6b65\u9a8c\u8bc1\u7801:", "en": "2FA Code:"},
	"login_btn":     {"zh": "\u767b\u5f55", "en": "Login"},
	"acc_info":      {"zh": "\u8d26\u53f7\u4fe1\u606f", "en": "Account Info"},
	"name":          {"zh": "\u540d\u79f0:", "en": "Name:"},
	"acc_email":     {"zh": "\u90ae\u7bb1:", "en": "Email:"},
	"fetch_info":    {"zh": "\u83b7\u53d6\u8d26\u53f7\u4fe1\u606f", "en": "Fetch Info"},
	"revoke":        {"zh": "\u540a\u9500\u51ed\u636e", "en": "Revoke"},
	"search_tab":    {"zh": "\u641c\u7d22", "en": "Search"},
	"search_label":  {"zh": "\u641c\u7d22\u5173\u952e\u8bcd:", "en": "Search Term:"},
	"limit":         {"zh": "\u6570\u91cf:", "en": "Limit:"},
	"platform_lbl":  {"zh": "\u5e73\u53f0:", "en": "Platform:"},
	"search_btn":    {"zh": "\u641c\u7d22", "en": "Search"},
	"results":       {"zh": "\u641c\u7d22\u7ed3\u679c:", "en": "Results:"},
	"col_name":      {"zh": "\u540d\u79f0", "en": "Name"},
	"col_bundle":    {"zh": "Bundle ID", "en": "Bundle ID"},
	"col_appid":     {"zh": "App ID", "en": "App ID"},
	"col_version":   {"zh": "\u7248\u672c", "en": "Version"},
	"col_price":     {"zh": "\u4ef7\u683c", "en": "Price"},
	"dl_tab":        {"zh": "\u4e0b\u8f7d", "en": "Download"},
	"bundle_id":     {"zh": "Bundle ID:", "en": "Bundle ID:"},
	"app_id":        {"zh": "App ID:", "en": "App ID:"},
	"out_path":      {"zh": "\u4fdd\u5b58\u8def\u5f84:", "en": "Output Path:"},
	"browse":        {"zh": "\u6d4f\u89c8...", "en": "Browse..."},
	"dl_version":    {"zh": "External Version ID:", "en": "External Version ID:"},
	"auto_purchase": {"zh": "\u81ea\u52a8\u83b7\u53d6\u8bb8\u53ef\u8bc1", "en": "Auto-purchase license"},
	"dl_btn":        {"zh": "\u5f00\u59cb\u4e0b\u8f7d", "en": "Download"},
	"buy_tab":       {"zh": "\u8d2d\u4e70", "en": "Purchase"},
	"buy_note":      {"zh": "\u4ec5\u652f\u6301\u514d\u8d39\u5e94\u7528\u7684\u8bb8\u53ef\u8bc1\u83b7\u53d6\u3002", "en": "Only free app licenses."},
	"buy_btn":       {"zh": "\u83b7\u53d6\u8bb8\u53ef\u8bc1", "en": "Get License"},
	"ver_tab":       {"zh": "\u7248\u672c", "en": "Versions"},
	"list_ver":      {"zh": "\u5217\u51fa\u7248\u672c", "en": "List Versions"},
	"list_btn":      {"zh": "\u5217\u51fa\u7248\u672c", "en": "List"},
	"ver_meta":      {"zh": "\u7248\u672c\u5143\u6570\u636e", "en": "Version Metadata"},
	"meta_btn":      {"zh": "\u83b7\u53d6\u5143\u6570\u636e", "en": "Get Metadata"},
	"settings":      {"zh": "\u8bbe\u7f6e", "en": "Settings"},
	"lang_label":    {"zh": "\u8bed\u8a00 / Language:", "en": "Language:"},
	"ready":         {"zh": "\u5c31\u7eea", "en": "Ready"},
	"error":         {"zh": "\u9519\u8bef", "en": "Error"},
	"success":       {"zh": "\u6210\u529f", "en": "Success"},
	"confirm":       {"zh": "\u786e\u8ba4", "en": "Confirm"},
	"free":          {"zh": "\u514d\u8d39", "en": "Free"},
	"account":       {"zh": "\u8d26\u53f7", "en": "Account"},
	"login_fail":    {"zh": "\u767b\u5f55\u5931\u8d25", "en": "Login Failed"},
	"login_ok":      {"zh": "\u767b\u5f55\u6210\u529f: ", "en": "Logged in: "},
	"search_fail":   {"zh": "\u641c\u7d22\u5931\u8d25", "en": "Search Failed"},
	"dl_fail":       {"zh": "\u4e0b\u8f7d\u5931\u8d25", "en": "Download Failed"},
	"dl_ok":         {"zh": "\u4e0b\u8f7d\u5b8c\u6210", "en": "Download Complete"},
	"saved_to":      {"zh": "\u4fdd\u5b58\u81f3:\n", "en": "Saved to:\n"},
	"already_own":   {"zh": "\u4f60\u5df2\u7ecf\u62e5\u6709\u6b64\u5e94\u7528\u7684\u8bb8\u53ef\u8bc1", "en": "You already own this app."},
	"license_ok":    {"zh": "\u8bb8\u53ef\u8bc1\u83b7\u53d6\u6210\u529f", "en": "License acquired."},
	"create_fail":   {"zh": "\u521b\u5efa\u7a97\u53e3\u5931\u8d25", "en": "Failed to create window"},
	"init_fail":     {"zh": "\u521d\u59cb\u5316\u5931\u8d25", "en": "Initialization failed"},
	"enter_pw":      {"zh": "\u8bf7\u8f93\u5165\u5bc6\u94a5\u94fe\u5bc6\u7801", "en": "Enter keychain passphrase"},
	"enter_email":   {"zh": "\u8bf7\u8f93\u5165 Apple ID \u90ae\u7bb1\u548c\u5bc6\u7801", "en": "Enter Apple ID and password"},
	"enter_term":    {"zh": "\u8bf7\u8f93\u5165\u641c\u7d22\u5173\u952e\u8bcd", "en": "Enter a search term"},
	"enter_app":     {"zh": "\u8bf7\u586b\u5199 Bundle ID \u6216 App ID", "en": "Enter Bundle ID or App ID"},
	"enter_bundle":  {"zh": "\u8bf7\u8f93\u5165 Bundle ID", "en": "Enter Bundle ID"},
	"enter_ver_id":  {"zh": "\u8bf7\u8f93\u5165 External Version ID", "en": "Enter External Version ID"},
	"login_ing":     {"zh": "\u6b63\u5728\u767b\u5f55...", "en": "Logging in..."},
	"search_ing":    {"zh": "\u6b63\u5728\u641c\u7d22...", "en": "Searching..."},
	"dl_ing":        {"zh": "\u6b63\u5728\u4e0b\u8f7d\uff0c\u8bf7\u7a0d\u5019...", "en": "Downloading..."},
	"buy_ing":       {"zh": "\u6b63\u5728\u83b7\u53d6\u8bb8\u53ef\u8bc1...", "en": "Getting license..."},
	"ver_ing":       {"zh": "\u6b63\u5728\u83b7\u53d6\u7248\u672c\u5217\u8868...", "en": "Fetching versions..."},
	"meta_ing":      {"zh": "\u6b63\u5728\u83b7\u53d6\u7248\u672c\u5143\u6570\u636e...", "en": "Fetching metadata..."},
	"found_results": {"zh": "\u627e\u5230 %d \u4e2a\u7ed3\u679c", "en": "Found %d results"},
	"found_vers":    {"zh": "\u627e\u5230 %d \u4e2a\u7248\u672c", "en": "Found %d versions"},
	"total_vers":    {"zh": "\u5171 %d \u4e2a\u7248\u672c:", "en": "Total %d versions:"},
	"ver_num":       {"zh": "\u7248\u672c\u53f7", "en": "Version"},
	"rel_date":      {"zh": "\u53d1\u5e03\u65e5\u671f", "en": "Release Date"},
	"revoke_confirm": {"zh": "\u786e\u5b9a\u8981\u540a\u9500 App Store \u51ed\u636e\u5417\uff1f", "en": "Revoke App Store credentials?"},
	"revoked":       {"zh": "\u51ed\u636e\u5df2\u540a\u9500", "en": "Credentials revoked"},
	"fetch_ing":     {"zh": "\u6b63\u5728\u83b7\u53d6\u8d26\u53f7\u4fe1\u606f...", "en": "Fetching account info..."},
	"acc_label":     {"zh": "\u8d26\u53f7: ", "en": "Account: "},
	"keychain_help": {"zh": "\u5bc6\u94a5\u94fe\u7528\u4e8e\u5b58\u50a8 Apple \u767b\u5f55\u51ed\u636e\uff0c\u8bf7\u5148\u5c1d\u8bd5\u8bbe\u5907\u7684\u9501\u5c4f\u754c\u9762\u5bc6\u7801\u3002", "en": "Stores Apple credentials. Try your device lock screen password first."},
	"ctx_dl":        {"zh": "\u4e0b\u8f7d\u6b64\u5e94\u7528", "en": "Download this app"},
	"ctx_buy":       {"zh": "\u83b7\u53d6\u6b64\u5e94\u7528\u8bb8\u53ef\u8bc1", "en": "Get license"},
	"ctx_ver":       {"zh": "\u67e5\u770b\u7248\u672c\u5217\u8868", "en": "View versions"},
	"copy_bundle":   {"zh": "\u590d\u5236 Bundle ID", "en": "Copy Bundle ID"},
	"copy_appid":    {"zh": "\u590d\u5236 App ID", "en": "Copy App ID"},
	"copied":        {"zh": "\u5df2\u590d\u5236", "en": "Copied"},
}

func T(key string) string {
	if v, ok := tr[key]; ok {
		l := effectiveLang()
		if s, ok2 := v[l]; ok2 { return s }
	}
	return key
}

type i18nUpdater struct {
	syncText func(string)
	key      string
}

var i18nWidgets []i18nUpdater

func regI18n(syncText func(string), key string) {
	i18nWidgets = append(i18nWidgets, i18nUpdater{func(s string) {
		defer func() { recover() }()
		syncText(s)
	}, key})
}

func rebuildI18n() {
	for _, w := range i18nWidgets {
		w.syncText(T(w.key))
	}
}

var (
	appStore           appstore.AppStore
	keychainPassphrase string
	lastPassword       string

	mainWin     *walk.MainWindow
	statusLabel *walk.Label
	tabWidget   *walk.TabWidget

	unlockPassEdit *walk.LineEdit
	loginEmailEdit *walk.LineEdit
	loginPassEdit  *walk.LineEdit
	login2FAEdit   *walk.LineEdit
	infoNameLabel  *walk.Label
	infoEmailLabel *walk.Label

	searchTermEdit      *walk.LineEdit
	searchLimitEdit     *walk.LineEdit
	searchPlatformCombo *walk.ComboBox
	searchTable         *walk.TableView
	searchModel         *AppSearchModel

	dlBundleEdit    *walk.LineEdit
	dlAppIDEdit     *walk.LineEdit
	dlOutputEdit    *walk.LineEdit
	dlPlatformCombo *walk.ComboBox
	dlVersionEdit   *walk.LineEdit
	dlPurchaseCheck *walk.CheckBox

	purchaseBundleEdit *walk.LineEdit

	verBundleEdit  *walk.LineEdit
	verAppIDEdit   *walk.LineEdit
	verListBox     *walk.ListBox
	verStore       []string
	metaBundleEdit *walk.LineEdit
	metaAppIDEdit  *walk.LineEdit
	metaVersionEdit *walk.LineEdit
	metaResultEdit *walk.TextEdit

	groupBoxKeychain *walk.GroupBox
	groupBoxLogin    *walk.GroupBox
	groupBoxAccInfo  *walk.GroupBox
	groupBoxListVer  *walk.GroupBox
	groupBoxVerMeta  *walk.GroupBox

	lblKeychainPw   *walk.Label
	btnUnlock       *walk.PushButton
	lblKeychainHelp *walk.Label
	lblEmail        *walk.Label
	lblPass         *walk.Label
	lbl2FA          *walk.Label
	btnLogin        *walk.PushButton
	lblName         *walk.Label
	lblAccEmail     *walk.Label
	btnFetchInfo    *walk.PushButton
	btnRevoke       *walk.PushButton
	lblSearchTerm   *walk.Label
	lblLimit        *walk.Label
	lblPlatform     *walk.Label
	btnSearch       *walk.PushButton
	lblResults      *walk.Label
	lblBundle       *walk.Label
	lblAppID        *walk.Label
	lblOutPath      *walk.Label
	lblDlVersion    *walk.Label
	btnDownload     *walk.PushButton
	dlProgressLabel *walk.Label
	dlProgressBar   *walk.ProgressBar
	btnBrowse       *walk.PushButton
	lblBuyNote      *walk.Label
	btnBuy          *walk.PushButton
	lblBuyHint      *walk.Label
	btnListVer      *walk.PushButton
	btnMeta         *walk.PushButton
	lblLang         *walk.Label
	btnSearchDl     *walk.PushButton
	btnSearchBuy    *walk.PushButton
	btnSearchVer    *walk.PushButton
	btnCopyBid      *walk.PushButton
	btnCopyAid      *walk.PushButton
)

type AppSearchModel struct {
	walk.TableModelBase
	items []appstore.App
}

func (m *AppSearchModel) RowCount() int { return len(m.items) }
func (m *AppSearchModel) Value(row, col int) interface{} {
	if row >= len(m.items) { return "" }
	a := m.items[row]
	switch col {
	case 0: return a.Name
	case 1: return a.BundleID
	case 2: return a.ID
	case 3: return a.Version
	case 4:
		if a.Price == 0 { return T("free") }
		return fmt.Sprintf("$%.2f", a.Price)
	}
	return ""
}

func selectedApp() (int64, string) {
	if searchModel == nil || searchTable == nil { return 0, "" }
	idx := searchTable.CurrentIndex()
	if idx < 0 || idx >= len(searchModel.items) { return 0, "" }
	a := searchModel.items[idx]
	return a.ID, a.BundleID
}

func initDependencies() {
	writer := zerolog.SyncWriter(os.Stdout)
	logger := log.NewLogger(log.Args{Verbose: false, Writer: writer})
	ops := operatingsystem.New()
	mach := machine.New(machine.Args{OS: ops})

	jar := util.Must(cookiejar.New(&cookiejar.Options{
		Filename: filepath.Join(mach.HomeDirectory(), configDirectoryName, cookieJarFileName),
	}))

	ring := util.Must(keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.SecretServiceBackend,
			keyring.FileBackend,
		},
		ServiceName: keychainServiceName,
		FileDir:     filepath.Join(mach.HomeDirectory(), configDirectoryName),
		FilePasswordFunc: func(s string) (string, error) {
			if keychainPassphrase == "" {
				return "", fmt.Errorf("keychain passphrase required: %s", s)
			}
			return keychainPassphrase, nil
		},
	}))

	keyChain := keychain.New(keychain.Args{Keyring: ring})

	configDir := filepath.Join(mach.HomeDirectory(), configDirectoryName)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		_ = os.MkdirAll(configDir, 0700)
	}

	appStore = appstore.NewAppStore(appstore.Args{
		CookieJar:       jar,
		OperatingSystem: ops,
		Keychain:        keyChain,
		Machine:         mach,
	})
	_ = logger
}

func safeInitDeps() {
	defer func() {
		if r := recover(); r != nil {
			walk.MsgBox(nil, T("init_fail"), fmt.Sprintf("%v", r), walk.MsgBoxIconError)
			os.Exit(1)
		}
	}()
	initDependencies()
}

func setStatus(msg string) {
	if statusLabel != nil { statusLabel.SetText(msg) }
}

func showError(msg string) {
	walk.MsgBox(mainWin, T("error"), msg, walk.MsgBoxIconError)
}

func showInfo(msg string) {
	walk.MsgBox(mainWin, T("success"), msg, walk.MsgBoxIconInformation)
}

func toInt(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return v
}

func switchToTab(idx int) {
	if tabWidget != nil {
		tabWidget.SetCurrentIndex(idx)
	}
}

func saveConfig() {
	home, _ := os.UserHomeDir()
	os.WriteFile(filepath.Join(home, ".ipatool", "gui-passphrase.txt"), []byte(keychainPassphrase), 0600)
}

func loadConfig() {
	home, _ := os.UserHomeDir()
	data, err := os.ReadFile(filepath.Join(home, ".ipatool", "gui-passphrase.txt"))
	if err == nil && len(data) > 0 {
		keychainPassphrase = strings.TrimSpace(string(data))
	}
}

func refreshToken(acc appstore.Account) (appstore.Account, error) {
	bag, err := appStore.Bag(appstore.BagInput{})
	if err != nil { return acc, err }
	result, err := appStore.Login(appstore.LoginInput{
		Email: acc.Email, Password: lastPassword, Endpoint: bag.AuthEndpoint,
	})
	if err != nil { return acc, err }
	return result.Account, nil
}

func handleUnlock() {
	pass := unlockPassEdit.Text()
	if pass == "" { showError(T("enter_pw")); return }
	keychainPassphrase = pass
	safeInitDeps()
	setStatus(T("unlock_ok"))
	saveConfig()
	showInfo(T("unlocked"))
}

func handleLogin() {
	if loginEmailEdit.Text() == "" || loginPassEdit.Text() == "" { showError(T("enter_email")); return }
	if kp := unlockPassEdit.Text(); kp != "" && keychainPassphrase == "" { keychainPassphrase = kp; safeInitDeps() }
	setStatus(T("login_ing"))
	bag, err := appStore.Bag(appstore.BagInput{})
	if err != nil { showError(fmt.Sprintf("Bag: %v", err)); return }
	result, err := appStore.Login(appstore.LoginInput{Email: loginEmailEdit.Text(), Password: loginPassEdit.Text(), AuthCode: login2FAEdit.Text(), Endpoint: bag.AuthEndpoint})
	if err != nil { walk.MsgBox(mainWin, T("login_fail"), err.Error(), walk.MsgBoxIconError); setStatus(T("login_fail")); return }
	infoNameLabel.SetText(result.Account.Name)
	infoEmailLabel.SetText(result.Account.Email)
	lastPassword = loginPassEdit.Text()
	saveConfig()
	setStatus(T("login_ok") + result.Account.Name)
}

func handleAccountInfo() {
	setStatus(T("fetch_ing"))
	result, err := appStore.AccountInfo()
	if err != nil { showError(err.Error()); return }
	infoNameLabel.SetText(result.Account.Name)
	infoEmailLabel.SetText(result.Account.Email)
	setStatus(T("acc_label") + result.Account.Name)
}

func handleRevoke() {
	if walk.MsgBox(mainWin, T("confirm"), T("revoke_confirm"), walk.MsgBoxIconWarning|walk.MsgBoxYesNo) != walk.DlgCmdYes { return }
	if err := appStore.Revoke(); err != nil { showError(err.Error()); return }
	infoNameLabel.SetText(""); infoEmailLabel.SetText("")
	setStatus(T("revoked"))
}

func handleSearch() {
	term := searchTermEdit.Text()
	if term == "" { showError(T("enter_term")); return }
	setStatus(T("search_ing"))
	infoResult, err := appStore.AccountInfo()
	if err != nil { showError(err.Error()); return }
	platform := appstore.PlatformIPhone
	if searchPlatformCombo.CurrentIndex() == 1 { platform = appstore.PlatformIPad
	} else if searchPlatformCombo.CurrentIndex() == 2 { platform = appstore.PlatformAppleTV }
	result, err := appStore.Search(appstore.SearchInput{Account: infoResult.Account, Term: term, Limit: toInt(searchLimitEdit.Text()), Platform: platform})
	if err != nil { walk.MsgBox(mainWin, T("search_fail"), err.Error(), walk.MsgBoxIconError); setStatus(T("search_fail")); return }
	searchModel.items = result.Results
	searchModel.PublishRowsReset()
	setStatus(fmt.Sprintf(T("found_results"), result.Count))
}

func handleDownload() {
	appID := toInt(dlAppIDEdit.Text()); bundleID := dlBundleEdit.Text()
	if appID == 0 && bundleID == "" { showError(T("enter_app")); return }
	setStatus(T("dl_ing"))
	go func() {
		// Progress polling
		done := make(chan bool)
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					if dlProgressLabel != nil {
						mainWin.Synchronize(func() { dlProgressLabel.SetText(T("dl_ing")) })
					}
					time.Sleep(500 * time.Millisecond)
				}
			}
		}()
		defer close(done)

		platform := appstore.PlatformIPhone
		if dlPlatformCombo.CurrentIndex() == 1 { platform = appstore.PlatformIPad
		} else if dlPlatformCombo.CurrentIndex() == 2 { platform = appstore.PlatformAppleTV }
		infoResult, err := appStore.AccountInfo()
		if err != nil { mainWin.Synchronize(func() { showError(err.Error()) }); return }
		acc := infoResult.Account; app := appstore.App{ID: appID}
		if bundleID != "" {
			lr, err := appStore.Lookup(appstore.LookupInput{Account: acc, BundleID: bundleID, Platform: platform})
			if err != nil { mainWin.Synchronize(func() { showError(err.Error()) }); return }
			app = lr.App
		}
		if dlPurchaseCheck.Checked() {
			err := appStore.Purchase(appstore.PurchaseInput{Account: acc, App: app})
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				if strings.Contains(err.Error(), "auth code") {
					mainWin.Synchronize(func() { showError("2FA required. Please re-login.") })
					return
				}
				if strings.Contains(err.Error(), "password token is expired") {
					acc, err = refreshToken(acc)
					if err == nil { err = appStore.Purchase(appstore.PurchaseInput{Account: acc, App: app}) }
				}
				if err != nil && !strings.Contains(err.Error(), "already exists") {
					mainWin.Synchronize(func() { showError(err.Error()) })
					return
				}
			}
		}
		out, err := appStore.Download(appstore.DownloadInput{Account: acc, App: app, OutputPath: dlOutputEdit.Text(), Progress: nil, ExternalVersionID: dlVersionEdit.Text(), Platform: platform})
		if err != nil {
			mainWin.Synchronize(func() { walk.MsgBox(mainWin, T("dl_fail"), err.Error(), walk.MsgBoxIconError); setStatus(T("dl_fail")) })
			return
		}
		err = appStore.ReplicateSinf(appstore.ReplicateSinfInput{Sinfs: out.Sinfs, PackagePath: out.DestinationPath})
		if err != nil { mainWin.Synchronize(func() { showError(err.Error()) }); return }
		mainWin.Synchronize(func() {
			setStatus(T("dl_ok") + ": " + out.DestinationPath)
			if dlProgressLabel != nil { dlProgressLabel.SetText("") }
			walk.MsgBox(mainWin, T("dl_ok"), T("saved_to")+out.DestinationPath, walk.MsgBoxIconInformation)
		})
	}()
}

func handleDownloadFromSearch() {
	id, bid := selectedApp()
	if id == 0 && bid == "" { showError(T("enter_app")); return }
	dlAppIDEdit.SetText(fmt.Sprintf("%d", id))
	dlBundleEdit.SetText(bid)
	switchToTab(2)
}

func handlePurchase() {
	bundleID := purchaseBundleEdit.Text()
	if bundleID == "" { showError(T("enter_bundle")); return }
	setStatus(T("buy_ing"))
	infoResult, err := appStore.AccountInfo()
	if err != nil { showError(err.Error()); return }
	acc := infoResult.Account
	lr, err := appStore.Lookup(appstore.LookupInput{Account: acc, BundleID: bundleID})
	if err != nil { showError(err.Error()); return }
	err = appStore.Purchase(appstore.PurchaseInput{Account: acc, App: lr.App})
	if err != nil && strings.Contains(err.Error(), "auth code is required") {
		showError("2FA code required. Please re-login with your 2FA code first.")
		return
	}
	if err != nil && !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "password token is expired") { showError(err.Error()); return }
	if err != nil && strings.Contains(err.Error(), "password token is expired") {
		acc, err = refreshToken(acc)
		if err == nil { err = appStore.Purchase(appstore.PurchaseInput{Account: acc, App: lr.App}) }
	}
	if err != nil && !strings.Contains(err.Error(), "already exists") { showError(err.Error()); return }
	if err != nil { setStatus(T("already_own")); showInfo(T("already_own"))
	} else { setStatus(T("license_ok")); showInfo(T("license_ok")) }
}

func handlePurchaseFromSearch() {
	id, bid := selectedApp()
	if id == 0 && bid == "" { showError(T("enter_app")); return }
	purchaseBundleEdit.SetText(bid)
	switchToTab(3)
}

func handleListVersions() {
	appID := toInt(verAppIDEdit.Text()); bundleID := verBundleEdit.Text()
	if appID == 0 && bundleID == "" { showError(T("enter_app")); return }
	setStatus(T("ver_ing"))
	infoResult, err := appStore.AccountInfo()
	if err != nil { showError(err.Error()); return }
	acc := infoResult.Account; app := appstore.App{ID: appID}
	if bundleID != "" {
		lr, err := appStore.Lookup(appstore.LookupInput{Account: acc, BundleID: bundleID})
		if err != nil { showError(err.Error()); return }
		app = lr.App
	}
	result, err := appStore.ListVersions(appstore.ListVersionsInput{Account: acc, App: app})
	if err != nil { showError(err.Error()); return }
verStore = result.ExternalVersionIdentifiers
	verListBox.SetModel(verStore)
	setStatus(fmt.Sprintf(T("found_vers"), len(result.ExternalVersionIdentifiers)))
}

func handleVersionsFromSearch() {
	id, bid := selectedApp()
	if id == 0 && bid == "" { showError(T("enter_app")); return }
	verAppIDEdit.SetText(fmt.Sprintf("%d", id))
	verBundleEdit.SetText(bid)
	switchToTab(4)
	handleListVersions()
}

func handleVersionMetadata() {
	appID := toInt(metaAppIDEdit.Text()); bundleID := metaBundleEdit.Text(); versionID := metaVersionEdit.Text()
	if appID == 0 && bundleID == "" { showError(T("enter_app")); return }
	if versionID == "" { showError(T("enter_ver_id")); return }
	setStatus(T("meta_ing"))
	infoResult, err := appStore.AccountInfo()
	if err != nil { showError(err.Error()); return }
	acc := infoResult.Account; app := appstore.App{ID: appID}
	if bundleID != "" {
		lr, err := appStore.Lookup(appstore.LookupInput{Account: acc, BundleID: bundleID})
		if err != nil { showError(err.Error()); return }
		app = lr.App
	}
	result, err := appStore.GetVersionMetadata(appstore.GetVersionMetadataInput{Account: acc, App: app, VersionID: versionID})
	if err != nil { showError(err.Error()); return }
	metaResultEdit.SetText(fmt.Sprintf(T("ver_num")+": %s\r\n"+T("rel_date")+": %s", result.DisplayVersion, result.ReleaseDate.Format("2006-01-02")))
	setStatus(T("ver_num") + ": " + result.DisplayVersion)
}

func handleBrowseOutput() {
	dlg := new(walk.FileDialog)
	dlg.Title = T("out_path")
	dlg.FilePath = dlOutputEdit.Text()
	dlg.Filter = "All Files (*.*)|*.*"
	if ok, _ := dlg.ShowSave(mainWin); ok {
		dlOutputEdit.SetText(filepath.Dir(dlg.FilePath))
	}
}

func switchLang(l string) {
	lang = l
	rebuildI18n()
	setStatus(T("ready"))
}

func g(children ...Widget) []Widget { return children }


func registerAllI18n() {
	// GroupBoxes
	regI18n(func(s string) { groupBoxKeychain.SetTitle(s) }, "keychain")
	regI18n(func(s string) { groupBoxLogin.SetTitle(s) }, "login_title")
	regI18n(func(s string) { groupBoxAccInfo.SetTitle(s) }, "acc_info")
	regI18n(func(s string) { groupBoxListVer.SetTitle(s) }, "list_ver")
	regI18n(func(s string) { groupBoxVerMeta.SetTitle(s) }, "ver_meta")

	// Account tab
	regI18n(func(s string) { lblKeychainPw.SetText(s) }, "keychain_pw")
	regI18n(func(s string) { btnUnlock.SetText(s) }, "unlock")
	regI18n(func(s string) { lblKeychainHelp.SetText(s) }, "keychain_help")
	regI18n(func(s string) { lblEmail.SetText(s) }, "email")
	regI18n(func(s string) { lblPass.SetText(s) }, "password")
	regI18n(func(s string) { lbl2FA.SetText(s) }, "2fa")
	regI18n(func(s string) { btnLogin.SetText(s) }, "login_btn")
	regI18n(func(s string) { lblName.SetText(s) }, "name")
	regI18n(func(s string) { lblAccEmail.SetText(s) }, "acc_email")
	regI18n(func(s string) { btnFetchInfo.SetText(s) }, "fetch_info")
	regI18n(func(s string) { btnRevoke.SetText(s) }, "revoke")

	// Search tab
	regI18n(func(s string) { lblSearchTerm.SetText(s) }, "search_label")
	regI18n(func(s string) { lblLimit.SetText(s) }, "limit")
	regI18n(func(s string) { lblPlatform.SetText(s) }, "platform_lbl")
	regI18n(func(s string) { btnSearch.SetText(s) }, "search_btn")
	regI18n(func(s string) { lblResults.SetText(s) }, "results")

	// Download tab
	regI18n(func(s string) { lblBundle.SetText(s) }, "bundle_id")
	regI18n(func(s string) { lblAppID.SetText(s) }, "app_id")
	regI18n(func(s string) { lblOutPath.SetText(s) }, "out_path")
	regI18n(func(s string) { lblDlVersion.SetText(s) }, "dl_version")
	regI18n(func(s string) { dlPurchaseCheck.SetText(s) }, "auto_purchase")
	regI18n(func(s string) { btnDownload.SetText(s) }, "dl_btn")
	regI18n(func(s string) { btnBrowse.SetText(s) }, "browse")

	// Purchase tab
	regI18n(func(s string) { lblBuyNote.SetText(s) }, "buy_note")
	regI18n(func(s string) { btnBuy.SetText(s) }, "buy_btn")

	// Versions tab
	regI18n(func(s string) { btnListVer.SetText(s) }, "list_btn")
	regI18n(func(s string) { btnMeta.SetText(s) }, "meta_btn")

	// Settings
	regI18n(func(s string) { lblLang.SetText(s) }, "lang_label")

	// Status
	regI18n(func(s string) { statusLabel.SetText(s) }, "ready")

}

func main() {
	syscall.NewLazyDLL("comctl32.dll").NewProc("InitCommonControls").Call()
	safeInitDeps()
	loadConfig()
	if keychainPassphrase != "" { initDependencies() }
	searchModel = new(AppSearchModel)

	if err := (MainWindow{
		AssignTo: &mainWin,
		Title:    "ipatool GUI",
		MinSize:  Size{Width: 860, Height: 640},
		Size:     Size{Width: 920, Height: 680},
		Layout:   VBox{MarginsZero: true},
		Children: []Widget{
			TabWidget{
				AssignTo: &tabWidget,
				Pages: []TabPage{
					{
						Title:  T("account"),
						Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
						Children: g(
							GroupBox{AssignTo: &groupBoxKeychain, Title: T("keychain"), Layout: VBox{Spacing: 6}, Children: g(
								Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
									Label{AssignTo: &lblKeychainPw, Text: T("keychain_pw")},
									LineEdit{AssignTo: &unlockPassEdit, PasswordMode: true},
								)},
								PushButton{AssignTo: &btnUnlock, Text: T("unlock"), OnClicked: handleUnlock},
								Label{AssignTo: &lblKeychainHelp, Text: T("keychain_help")},
							)},
							GroupBox{AssignTo: &groupBoxLogin, Title: T("login_title"), Layout: VBox{Spacing: 6}, Children: g(
								Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
									Label{AssignTo: &lblEmail, Text: T("email")},
									LineEdit{AssignTo: &loginEmailEdit},
									Label{AssignTo: &lblPass, Text: T("password")},
									LineEdit{AssignTo: &loginPassEdit, PasswordMode: true},
									Label{AssignTo: &lbl2FA, Text: T("2fa")},
									LineEdit{AssignTo: &login2FAEdit},
								)},
								PushButton{AssignTo: &btnLogin, Text: T("login_btn"), OnClicked: handleLogin, MaxSize: Size{Width: 80, Height: 24}},
							)},
							GroupBox{AssignTo: &groupBoxAccInfo, Title: T("acc_info"), Layout: VBox{Spacing: 6}, Children: g(
								Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
									Label{AssignTo: &lblName, Text: T("name")},
									Label{AssignTo: &infoNameLabel, Text: "-"},
									Label{AssignTo: &lblAccEmail, Text: T("acc_email")},
									Label{AssignTo: &infoEmailLabel, Text: "-"},
								)},
								Composite{Layout: HBox{Spacing: 6}, Children: g(
									PushButton{AssignTo: &btnFetchInfo, Text: T("fetch_info"), OnClicked: handleAccountInfo},
									PushButton{AssignTo: &btnRevoke, Text: T("revoke"), OnClicked: handleRevoke},
								)},
							)},
						),
					},
					{
						Title:  T("search_tab"),
						Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
						Children: g(
							Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
								Label{AssignTo: &lblSearchTerm, Text: T("search_label")},
								LineEdit{AssignTo: &searchTermEdit},
								Label{AssignTo: &lblLimit, Text: T("limit")},
								LineEdit{AssignTo: &searchLimitEdit, Text: "5"},
								Label{AssignTo: &lblPlatform, Text: T("platform_lbl")},
								ComboBox{AssignTo: &searchPlatformCombo, Model: []string{"iPhone", "iPad", "Apple TV"}, CurrentIndex: 0, Editable: false},
							)},
							PushButton{AssignTo: &btnSearch, Text: T("search_btn"), OnClicked: handleSearch, MaxSize: Size{Width: 80, Height: 24}},
							Label{AssignTo: &lblResults, Text: T("results")},
							TableView{AssignTo: &searchTable, Columns: []TableViewColumn{
								{Title: T("col_name"), Width: 200}, {Title: T("col_bundle"), Width: 200},
								{Title: T("col_appid"), Width: 80}, {Title: T("col_version"), Width: 80},
								{Title: T("col_price"), Width: 70},
							}, Model: searchModel, MultiSelection: false,
							},
							Composite{Layout: HBox{Spacing: 6}, Children: g(
								PushButton{AssignTo: &btnSearchDl, Text: T("ctx_dl"), OnClicked: handleDownloadFromSearch, MaxSize: Size{Width: 100, Height: 24}},
								PushButton{AssignTo: &btnSearchBuy, Text: T("ctx_buy"), OnClicked: handlePurchaseFromSearch, MaxSize: Size{Width: 100, Height: 24}},
								PushButton{AssignTo: &btnSearchVer, Text: T("ctx_ver"), OnClicked: handleVersionsFromSearch, MaxSize: Size{Width: 100, Height: 24}},
								PushButton{AssignTo: &btnCopyBid, Text: T("copy_bundle"), OnClicked: func() { _, bid := selectedApp(); if bid != "" { walk.Clipboard().SetText(bid); setStatus(T("copied") + ": " + bid) } }, MaxSize: Size{Width: 110, Height: 24}},
								PushButton{AssignTo: &btnCopyAid, Text: T("copy_appid"), OnClicked: func() { id, _ := selectedApp(); if id != 0 { s := fmt.Sprintf("%d", id); walk.Clipboard().SetText(s); setStatus(T("copied") + ": " + s) } }, MaxSize: Size{Width: 100, Height: 24}},
							)},
						),
					},
					{
						Title:  T("dl_tab"),
						Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
						Children: g(
							Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
								Label{Text: T("bundle_id")},
								LineEdit{AssignTo: &dlBundleEdit},
								Label{Text: T("app_id")},
								LineEdit{AssignTo: &dlAppIDEdit},
								Label{Text: T("out_path")},
								Composite{Layout: HBox{Spacing: 4}, Children: g(
									LineEdit{AssignTo: &dlOutputEdit},
									PushButton{AssignTo: &btnBrowse, Text: T("browse"), OnClicked: handleBrowseOutput, MaxSize: Size{Width: 70, Height: 24}},
								)},
								Label{AssignTo: &lblPlatform, Text: T("platform_lbl")},
								ComboBox{AssignTo: &dlPlatformCombo, Model: []string{"iPhone", "iPad", "Apple TV"}, CurrentIndex: 0, Editable: false},
								Label{Text: T("dl_version")},
								LineEdit{AssignTo: &dlVersionEdit},
							)},
							CheckBox{AssignTo: &dlPurchaseCheck, Text: T("auto_purchase")},
							PushButton{AssignTo: &btnDownload, Text: T("dl_btn"), OnClicked: handleDownload, MaxSize: Size{Width: 80, Height: 24}},
							Label{AssignTo: &dlProgressLabel, Text: ""},
							ProgressBar{AssignTo: &dlProgressBar, MinSize: Size{Width: 0, Height: 16}},
						),
					},
					{
						Title:  T("buy_tab"),
						Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
						Children: g(
							Label{AssignTo: &lblBuyNote, Text: T("buy_note")},
							Label{AssignTo: &lblBuyHint, Text: "If token expired, re-login on Account tab."},
							Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
								Label{Text: T("bundle_id")},
								LineEdit{AssignTo: &purchaseBundleEdit},
							)},
							PushButton{AssignTo: &btnBuy, Text: T("buy_btn"), OnClicked: handlePurchase, MaxSize: Size{Width: 90, Height: 24}},
						),
					},
					{
						Title:  T("ver_tab"),
						Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
						Children: g(
							GroupBox{AssignTo: &groupBoxListVer, Title: T("list_ver"), Layout: VBox{Spacing: 6}, Children: g(
								Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
									Label{Text: T("bundle_id")},
									LineEdit{AssignTo: &verBundleEdit},
									Label{Text: T("app_id")},
									LineEdit{AssignTo: &verAppIDEdit},
								)},
								PushButton{AssignTo: &btnListVer, Text: T("list_btn"), OnClicked: handleListVersions, MaxSize: Size{Width: 80, Height: 24}},
								PushButton{Text: "Use selected for download", OnClicked: func() {
									if verListBox != nil && verStore != nil && verListBox.CurrentIndex() >= 0 && verListBox.CurrentIndex() < len(verStore) {
										dlVersionEdit.SetText(verStore[verListBox.CurrentIndex()])
									}
								}, MaxSize: Size{Width: 160, Height: 24}},
								PushButton{Text: "Use selected for metadata", OnClicked: func() {
									if verListBox != nil && verStore != nil && verListBox.CurrentIndex() >= 0 && verListBox.CurrentIndex() < len(verStore) {
										metaVersionEdit.SetText(verStore[verListBox.CurrentIndex()])
									}
								}, MaxSize: Size{Width: 160, Height: 24}},
								ListBox{AssignTo: &verListBox, MinSize: Size{Width: 0, Height: 120},
								OnCurrentIndexChanged: func() {
									if verListBox != nil && verListBox.CurrentIndex() >= 0 {
										s := verStore[verListBox.CurrentIndex()]
										metaVersionEdit.SetText(s)
										dlVersionEdit.SetText(s)
									}
								},
							},
							)},
							GroupBox{AssignTo: &groupBoxVerMeta, Title: T("ver_meta"), Layout: VBox{Spacing: 6}, Children: g(
								Composite{Layout: Grid{Columns: 2, Spacing: 6}, Children: g(
									Label{Text: T("bundle_id")},
									LineEdit{AssignTo: &metaBundleEdit},
									Label{Text: T("app_id")},
									LineEdit{AssignTo: &metaAppIDEdit},
									Label{Text: T("dl_version")},
									LineEdit{AssignTo: &metaVersionEdit},
								)},
								PushButton{AssignTo: &btnMeta, Text: T("meta_btn"), OnClicked: handleVersionMetadata, MaxSize: Size{Width: 90, Height: 24}},
								TextEdit{AssignTo: &metaResultEdit, ReadOnly: true, MinSize: Size{Width: 0, Height: 60}},
							)},
						),
					},
					{
						Title:  T("settings"),
						Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
						Children: g(
							Composite{Layout: HBox{Spacing: 10}, Children: g(
								Label{AssignTo: &lblLang, Text: T("lang_label")},
								RadioButtonGroup{Buttons: []RadioButton{
									{Text: "System", OnClicked: func() { switchLang("system") }},
									{Text: "\u4e2d\u6587", OnClicked: func() { switchLang("zh") }},
									{Text: "English", OnClicked: func() { switchLang("en") }},
								}},
							)},
						),
					},
				},
			},
			Label{AssignTo: &statusLabel, Text: T("ready")},
		},
	}).Create(); err != nil {
		walk.MsgBox(nil, T("create_fail"), err.Error(), walk.MsgBoxIconError)
		os.Exit(1)
	}

	registerAllI18n()
	if keychainPassphrase != "" {
		mainWin.Synchronize(func() { handleAccountInfo() })
	}
	mainWin.Run()
}
