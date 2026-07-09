package scanner

// ================================================================
// 三、VS Code / JetBrains IDE 插件及配置
// ================================================================
func toolsCatIDE() []Tool {
	return []Tool{
		{Name: "Thunder_Client",
			WinPaths:   []string{"${APPDATA}\\Code\\User\\globalStorage\\rangav.vscode-thunder-client", "${HOME}\\.vscode\\extensions\\rangav.vscode-thunder-client*"},
			MacPaths:   []string{"~/Library/Application Support/Code/User/globalStorage/rangav.vscode-thunder-client", "~/.vscode/extensions/rangav.vscode-thunder-client*"},
			LinuxPaths: []string{"${CONFIG}/Code/User/globalStorage/rangav.vscode-thunder-client", "~/.vscode/extensions/rangav.vscode-thunder-client*"},
			Extensions: []string{".json"}, MaxFileSize: mb(5)},
		{Name: "RapidAPI_Client",
			WinPaths:   []string{"${APPDATA}\\Code\\User\\globalStorage\\rapidapi.vscode-rapidapi-client"},
			MacPaths:   []string{"~/Library/Application Support/Code/User/globalStorage/rapidapi.vscode-rapidapi-client"},
			LinuxPaths: []string{"${CONFIG}/Code/User/globalStorage/rapidapi.vscode-rapidapi-client"},
			Extensions: []string{".json"}, MaxFileSize: mb(5)},
		{Name: "REST_Client_VSCode",
			WinPaths:   []string{"${APPDATA}\\Code\\User\\globalStorage\\humao.rest-client", "${HOME}\\.vscode\\extensions\\humao.rest-client*"},
			MacPaths:   []string{"~/Library/Application Support/Code/User/globalStorage/humao.rest-client", "~/.vscode/extensions/humao.rest-client*"},
			LinuxPaths: []string{"${CONFIG}/Code/User/globalStorage/humao.rest-client", "~/.vscode/extensions/humao.rest-client*"},
			Extensions: []string{".json", ".http"}, MaxFileSize: mb(5)},
		{Name: "httpYac",
			WinPaths:   []string{"${APPDATA}\\Code\\User\\globalStorage\\anweber.vscode-httpyac", "${HOME}\\.httpyac"},
			MacPaths:   []string{"~/Library/Application Support/Code/User/globalStorage/anweber.vscode-httpyac", "~/.httpyac"},
			LinuxPaths: []string{"${CONFIG}/Code/User/globalStorage/anweber.vscode-httpyac", "~/.httpyac"},
			Extensions: []string{".json", ".yaml", ".yml"}, MaxFileSize: mb(5)},
		{Name: "IntelliJ_HTTP_Client",
			WinPaths:   []string{"${APPDATA}\\JetBrains\\*\\scratches", "${HOME}\\.IntelliJIdea*\\config\\scratches"},
			MacPaths:   []string{"~/Library/Application Support/JetBrains/*/scratches", "~/Library/Preferences/*/scratches"},
			LinuxPaths: []string{"${CONFIG}/JetBrains/*/scratches", "~/.local/share/JetBrains/*/scratches"},
			Extensions: []string{".http", ".rest", ".xml"}, MaxFileSize: mb(5)},
		{Name: "VS_Code_Settings",
			WinPaths:   []string{"${APPDATA}\\Code\\User\\settings.json"},
			MacPaths:   []string{"~/Library/Application Support/Code/User/settings.json"},
			LinuxPaths: []string{"${CONFIG}/Code/User/settings.json"},
			Extensions: []string{".json"}, MaxFileSize: mb(1)},

		// ================================================================
		// 四、浏览器扩展和浏览器存储
		// ================================================================
		{Name: "Talend_API_Tester",
			WinPaths:   []string{"${LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\Extensions\\*talend*", "${LOCALAPPDATA}\\Microsoft\\Edge\\User Data\\Default\\Extensions\\*talend*"},
			MacPaths:   []string{"~/Library/Application Support/Google/Chrome/Default/Extensions/*talend*", "~/Library/Application Support/Microsoft Edge/Default/Extensions/*talend*"},
			LinuxPaths: []string{"${CONFIG}/google-chrome/Default/Extensions/*talend*", "${CONFIG}/microsoft-edge/Default/Extensions/*talend*"},
			Extensions: []string{".js", ".json"}, MaxFileSize: mb(2)},
		{Name: "Postman_Interceptor",
			WinPaths:   []string{"${LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\Extensions\\*postman*", "${LOCALAPPDATA}\\Microsoft\\Edge\\User Data\\Default\\Extensions\\*postman*"},
			MacPaths:   []string{"~/Library/Application Support/Google/Chrome/Default/Extensions/*postman*", "~/Library/Application Support/Microsoft Edge/Default/Extensions/*postman*"},
			LinuxPaths: []string{"${CONFIG}/google-chrome/Default/Extensions/*postman*", "${CONFIG}/microsoft-edge/Default/Extensions/*postman*"},
			Extensions: []string{".js", ".json"}, MaxFileSize: mb(2)},
		{Name: "Hoppscotch_Browser",
			WinPaths:   []string{"${LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb", "${LOCALAPPDATA}\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb", "${APPDATA}\\Mozilla\\Firefox\\Profiles"},
			MacPaths:   []string{"~/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb", "~/Library/Application Support/Microsoft Edge/Default/Local Storage/leveldb", "~/Library/Application Support/Firefox/Profiles"},
			LinuxPaths: []string{"${CONFIG}/google-chrome/Default/Local Storage/leveldb", "${CONFIG}/microsoft-edge/Default/Local Storage/leveldb", "~/.mozilla/firefox"},
			Extensions: []string{".log", ".ldb"}, MaxFileSize: mb(5)},
		{Name: "WebSocket_King_Browser",
			WinPaths:   []string{"${LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb", "${LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\IndexedDB"},
			MacPaths:   []string{"~/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb", "~/Library/Application Support/Google/Chrome/Default/IndexedDB"},
			LinuxPaths: []string{"${CONFIG}/google-chrome/Default/Local Storage/leveldb", "${CONFIG}/google-chrome/Default/IndexedDB"},
			Extensions: []string{".log", ".ldb", ".leveldb"}, MaxFileSize: mb(5)},
		{Name: "Browser_Cookies",
			WinPaths:   []string{"${LOCALAPPDATA}\\Google\\Chrome\\User Data\\Default\\Cookies", "${LOCALAPPDATA}\\Microsoft\\Edge\\User Data\\Default\\Cookies", "${APPDATA}\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite"},
			MacPaths:   []string{"~/Library/Application Support/Google/Chrome/Default/Cookies", "~/Library/Application Support/Microsoft Edge/Default/Cookies", "~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite"},
			LinuxPaths: []string{"${CONFIG}/google-chrome/Default/Cookies", "${CONFIG}/microsoft-edge/Default/Cookies", "~/.mozilla/firefox/*/cookies.sqlite"},
			Extensions: []string{".sqlite"}, MaxFileSize: mb(5)},
	}
}