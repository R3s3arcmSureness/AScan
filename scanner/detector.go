package scanner

import (
	"regexp"
	"strings"
	"sync"
)

// Finding 表示一次检测发现的敏感信息
type Finding struct {
	Tool     string // 来源工具名称
	FilePath string // 文件路径
	Line     int    // 行号（0 表示未知）
	Type     string // 类型（如 "AWS_Access_Key", "Bearer_Token"）
	Value    string // 脱敏后的值（前6后4字符）
	Severity string // 严重程度：Critical, High, Medium, Low
	Context  string // 匹配行上下文（截断至100字符）
}

// Pattern 定义一个敏感信息检测规则
type Pattern struct {
	Name     string         // 名称，如 "OpenAI_API_Key"
	Regex    *regexp.Regexp // 正则表达式
	Severity string         // 严重程度
}

// 包级变量：预编译的所有检测模式（只编译一次）
var (
	patterns     []Pattern
	patternsOnce sync.Once
)

// GetPatterns 返回所有敏感信息检测模式（只编译一次，返回缓存切片，只读勿改）
func GetPatterns() []Pattern {
	patternsOnce.Do(func() {
		patterns = []Pattern{
		// ==================== AI/LLM 服务 ====================
		{
			Name:     "OpenAI_API_Key",
			Regex:    regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9]{32,}`),
			Severity: "Critical",
		},
		{
			Name:     "OpenAI_Project_Key",
			Regex:    regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{32,}`),
			Severity: "Critical",
		},
		{
			Name:     "Anthropic_API_Key",
			Regex:    regexp.MustCompile(`sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{40,}`),
			Severity: "Critical",
		},
		{
			Name:     "Google_AI_API_Key",
			Regex:    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Severity: "Critical",
		},
		{
			Name:     "Cohere_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:cohere|CO_API_KEY)[=:\s]+['"]?([A-Za-z0-9]{32,40})['"]?`),
			Severity: "High",
		},

		// ==================== 云服务商 ====================
		{
			Name:     "AWS_Access_Key",
			Regex:    regexp.MustCompile(`(?i)(?:AKIA|ASIA)[0-9A-Z]{16}`),
			Severity: "Critical",
		},
		{
			Name:     "AWS_Secret_Key",
			Regex:    regexp.MustCompile(`(?i)aws(?:_|\s)?secret(?:_|\s)?(?:access\s*)?(?:key)?[=:\s]+['\"]?([A-Za-z0-9/+=]{40})`),
			Severity: "Critical",
		},
		{
			Name:     "Azure_ConnectionString",
			Regex:    regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`),
			Severity: "Critical",
		},
		{
			Name:     "GCP_Service_Account_Key",
			Regex:    regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"`),
			Severity: "Critical",
		},
		{
			Name:     "Aliyun_AccessKey",
			Regex:    regexp.MustCompile(`(?i)(?:LTAI|LTA)[A-Za-z0-9]{16,20}`),
			Severity: "Critical",
		},
		{
			Name:     "TencentCloud_SecretId",
			Regex:    regexp.MustCompile(`(?i)(?:AKID|TENCENT)[A-Za-z0-9]{32,48}`),
			Severity: "Critical",
		},
		{
			Name:     "HuaweiCloud_AK",
			Regex:    regexp.MustCompile(`(?i)(?:huawei|hw)(?:_|\s)?(?:access|ak)[_\-]?(?:key)?[=:\s]+['\"]?([A-Z0-9]{20,30})['\"]?`),
			Severity: "High",
		},

		// ==================== CI/CD / 开发平台 ====================
		{
			Name:     "GitHub_Token",
			Regex:    regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`),
			Severity: "Critical",
		},
		{
			Name:     "GitHub_PAT",
			Regex:    regexp.MustCompile(`github_pat_[A-Za-z0-9_]{36,255}`),
			Severity: "Critical",
		},
		{
			Name:     "GitLab_Token",
			Regex:    regexp.MustCompile(`(?:glpat|gldt)-[A-Za-z0-9\-_]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "GitLab_Runner_Token",
			Regex:    regexp.MustCompile(`(?i)GR1348941[A-Za-z0-9\-_]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "BitBucket_AppPassword",
			Regex:    regexp.MustCompile(`(?i)ATBB[A-Za-z0-9]{28,}`),
			Severity: "Critical",
		},
		{
			Name:     "Jenkins_Credential",
			Regex:    regexp.MustCompile(`(?i)(?:jenkins|credential).*(?:secret|password|token)[=:\s]+['\"]?([A-Za-z0-9+/=]{20,})`),
			Severity: "Critical",
		},
		{
			Name:     "DockerHub_Password",
			Regex:    regexp.MustCompile(`(?i)docker(?:_|\s)?(?:password|pass|token)[=:\s]+['\"]?([^\s'\"]+)`),
			Severity: "High",
		},

		// ==================== JWT / Bearer Token ====================
		{
			Name:     "JWT_Token",
			Regex:    regexp.MustCompile(`eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*`),
			Severity: "High",
		},
		{
			Name:     "Bearer_Token",
			Regex:    regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)`),
			Severity: "High",
		},
		{
			Name:     "OAuth_Access_Token",
			Regex:    regexp.MustCompile(`(?i)(?:access_token|auth_token|oauth_token)[=:\s]+['\"]?([A-Za-z0-9\-._~+/=]{20,})`),
			Severity: "Critical",
		},
		{
			Name:     "OAuth_Refresh_Token",
			Regex:    regexp.MustCompile(`(?i)(?:refresh_token)[=:\s]+['\"]?([A-Za-z0-9\-._~+/=]{20,})`),
			Severity: "Critical",
		},

		// ==================== 通用 API Key ====================
		{
			Name: "Generic_API_Key_Assignment",
			Regex: regexp.MustCompile(
				`(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|secret[_-]?key|app[_-]?key|app[_-]?secret|client[_-]?secret|client[_-]?id)[\s]*[=:][\s]*['"\x60]?([A-Za-z0-9+/=_-]{16,})['"\x60]?`,
			),
			Severity: "High",
		},
		{
			Name: "Generic_Token_Field",
			Regex: regexp.MustCompile(
				`(?i)"(?:token|secret|password|apikey|api_key|accessToken|access_token)"[\s]*:[\s]*"([A-Za-z0-9+/=_-]{16,})"`,
			),
			Severity: "High",
		},
		{
			Name: "Generic_Authorization_Header",
			Regex: regexp.MustCompile(
				`(?i)(?:Authorization|X-API-Key|X-Auth-Token)[\s]*:[\s]*([^\s]+)`,
			),
			Severity: "High",
		},

		// ==================== 数据库连接 ====================
		{
			Name:     "Database_Connection_String",
			Regex:    regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|postgresql|redis|sqlite)://[^:]+:[^@]+@[^\s]+`),
			Severity: "Critical",
		},
		{
			Name:     "JDBC_Connection",
			Regex:    regexp.MustCompile(`(?i)jdbc:(?:mysql|postgresql|oracle|sqlserver)://[^:]+:[^@]+@[^\s]+`),
			Severity: "Critical",
		},

		// ==================== 支付 / 短信服务 ====================
		{
			Name:     "Stripe_Secret_Key",
			Regex:    regexp.MustCompile(`(?:sk_live_|rk_live_)[0-9a-zA-Z]{24,}`),
			Severity: "Critical",
		},
		{
			Name:     "Stripe_Publishable_Key",
			Regex:    regexp.MustCompile(`pk_(?:live|test)_[0-9a-zA-Z]{24,}`),
			Severity: "Medium",
		},
		{
			Name:     "Twilio_Key",
			Regex:    regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
			Severity: "Critical",
		},
		{
			Name:     "SendGrid_API_Key",
			Regex:    regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{16,}`),
			Severity: "Critical",
		},

		// ==================== 私有仓库 / 包管理 ====================
		{
			Name:     "npm_Token",
			Regex:    regexp.MustCompile(`(?i)npm_[A-Za-z0-9]{36}`),
			Severity: "Critical",
		},
		{
			Name:     "PyPI_Token",
			Regex:    regexp.MustCompile(`(?i)pypi-[A-Za-z0-9\-_]{16,}`),
			Severity: "Critical",
		},
		{
			Name:     "RubyGems_API_Key",
			Regex:    regexp.MustCompile(`(?i)rubygems_[A-Za-z0-9]{48}`),
			Severity: "Critical",
		},

		// ==================== 其他 Web 服务 ====================
		{
			Name:     "Slack_Bot_Token",
			Regex:    regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-_]{10,}`),
			Severity: "Critical",
		},
		{
			Name:     "Slack_Webhook",
			Regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
			Severity: "High",
		},
		{
			Name:     "Telegram_Bot_Token",
			Regex:    regexp.MustCompile(`[0-9]+:[A-Za-z0-9\-_]{35}`),
			Severity: "High",
		},
		{
			Name:     "Discord_Webhook",
			Regex:    regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+`),
			Severity: "High",
		},
		{
			Name:     "Heroku_API_Key",
			Regex:    regexp.MustCompile(`(?i)HRKU-[A-Za-z0-9\-_]{24,}`),
			Severity: "Critical",
		},
		{
			Name:     "Shopify_Access_Token",
			Regex:    regexp.MustCompile(`(?:shpat|shpca|shppa)_[A-Za-z0-9]{32,}`),
			Severity: "Critical",
		},
		{
			Name:     "Firebase_Auth",
			Regex:    regexp.MustCompile(`(?i)(?:firebase|FIREBASE).*(?:apiKey|api_key)[\s]*[=:][\s]*['\"]?([A-Za-z0-9\-_]{20,})`),
			Severity: "High",
		},

		// ==================== 私钥 ====================
		{
			Name:     "RSA_Private_Key",
			Regex:    regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`),
			Severity: "Critical",
		},
		{
			Name:     "SSH_Private_Key",
			Regex:    regexp.MustCompile(`-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----`),
			Severity: "Critical",
		},
		{
			Name:     "EC_Private_Key",
			Regex:    regexp.MustCompile(`-----BEGIN\s+EC\s+PRIVATE\s+KEY-----`),
			Severity: "Critical",
		},
		{
			Name:     "PGP_Private_Key",
			Regex:    regexp.MustCompile(`-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`),
			Severity: "Critical",
		},

		// ==================== Basic Auth ====================
		{
			Name:     "Basic_Auth_Header",
			Regex:    regexp.MustCompile(`(?i)(?:basic|authorization)[\s]*[=:][\s]*['\"]?(?:Basic\s+)?([A-Za-z0-9+/=]{20,})`),
			Severity: "High",
		},

		// ==================== 环境变量格式 ====================
		{
			Name:     "Env_Var_Secret_Assignment",
			Regex:    regexp.MustCompile(`(?i)^\s*(?:export\s+)?([A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIALS?))[\s]*=[\s]*['\"]?([^\s'\"]{8,})`),
			Severity: "High",
		},

		// ==================== 常见 API 密钥值模式（宽松匹配） ====================
		{
			Name:     "Hex_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:key|token|secret|password)[\s]*[=:][\s]*['\"]?([0-9a-fA-F]{32,64})['\"]?`),
			Severity: "Low",
		},
		{
			Name:     "Base64_Like_Secret",
			Regex:    regexp.MustCompile(`(?i)(?:key|token|secret|password)[\s]*[=:][\s]*['\"]?([A-Za-z0-9+/=]{40,})['\"]?`),
			Severity: "Low",
		},

		// ==================== 新增云平台 / 部署平台 ====================
		{
			Name:     "Vercel_Token",
			Regex:    regexp.MustCompile(`(?i)vercel_[-A-Za-z0-9]{24,}`),
			Severity: "Critical",
		},
		{
			Name:     "Netlify_Access_Token",
			Regex:    regexp.MustCompile(`(?i)nf(?:s|p|pt|u|a|o|ap|dp|ct|pm|po|pa|wa|wb|wd|we|wf|wg|wh|wi|wj|wk|wl|wm|wn|wo|wp|wq|wr|ws|wt|wu|wv|ww|wx|wy|wz|xa|xb|xc|xd|xe|xf|xg|xh|xi|xj|xk|xl|xm|xn|xo|xp|xq|xr|xs|xt|xu|xv|xw|xx|xy|xz|ya|yb|yc|yd|ye|yf|yg|yh|yi|yj|yk|yl|ym|yn|yo|yp|yq|yr|ys|yt|yu|yv|yw|yx|yy|yz)[-_A-Za-z0-9]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "Cloudflare_Global_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:cloudflare|CF_?API_?Key)[=:\s]+['\"]?([A-Za-z0-9]{37})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Cloudflare_API_Token",
			Regex:    regexp.MustCompile(`(?i)CF_API_TOKEN[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "DigitalOcean_PAT",
			Regex:    regexp.MustCompile(`dop_v1_[A-Za-z0-9_-]{40,}`),
			Severity: "Critical",
		},
		{
			Name:     "DigitalOcean_OAuth_Token",
			Regex:    regexp.MustCompile(`(?i)do_(?:o|a|s|d|f|g|h|j|k|l|z|x|c|v|b|n|m)[a-z0-9_-]{32,}`),
			Severity: "Critical",
		},
		{
			Name:     "Supabase_Service_Role_Key",
			Regex:    regexp.MustCompile(`(?i)supabase[-_]service[-_]role[-_]key[=:\s]+['\"]?([A-Za-z0-9._-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Supabase_Anon_Key",
			Regex:    regexp.MustCompile(`(?i)supabase[-_]anon[-_]key[=:\s]+['\"]?([A-Za-z0-9._-]{40,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "HashiCorp_Vault_Token",
			Regex:    regexp.MustCompile(`(?:hvs\.[A-Za-z0-9_-]{36,}|hvb\.[A-Za-z0-9_-]{36,})`),
			Severity: "Critical",
		},
		{
			Name:     "Datadog_API_Key",
			Regex:    regexp.MustCompile(`(?i)datadog[-_]?(?:api|app)[-_]?key[=:\s]+['\"]?([0-9a-f]{40})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "New_Relic_API_Key",
			Regex:    regexp.MustCompile(`NRAK-[A-Za-z0-9]{27}`),
			Severity: "Critical",
		},
		{
			Name:     "New_Relic_License_Key",
			Regex:    regexp.MustCompile(`(?i)NEW_RELIC_LICENSE_KEY[=:\s]+['\"]?([A-Za-z0-9]{40})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Pulumi_Access_Token",
			Regex:    regexp.MustCompile(`pul-[A-Za-z0-9_-]{40,}`),
			Severity: "Critical",
		},
		{
			Name:     "Sentry_DSN",
			Regex:    regexp.MustCompile(`https://[a-f0-9]{32}@[a-z0-9]+\.(?:sentry|ingest)\.(?:sentry\.io|sentry\.dev)/[0-9]+`),
			Severity: "High",
		},
		{
			Name:     "Databricks_PAT",
			Regex:    regexp.MustCompile(`dapi[a-f0-9]{32}`),
			Severity: "Critical",
		},
		{
			Name:     "MongoDB_Atlas_Key",
			Regex:    regexp.MustCompile(`(?i)mongodb(?:\+srv)?://[^:]+:[^@]+@[a-z0-9.-]+\.mongodb\.net`),
			Severity: "Critical",
		},
		{
			Name:     "Algolia_API_Key",
			Regex:    regexp.MustCompile(`(?i)algolia[-_]?(?:api|admin|search)[-_]?key[=:\s]+['\"]?([A-Za-z0-9]{32})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Auth0_Client_Secret",
			Regex:    regexp.MustCompile(`(?i)auth0[-_]client[-_]secret[=:\s]+['\"]?([A-Za-z0-9_-]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Okta_API_Token",
			Regex:    regexp.MustCompile(`(?i)okta[-_]?(?:api_?)?token[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Azure_Storage_Key",
			Regex:    regexp.MustCompile(`(?i)(?:azure[-_]?storage[-_]?(?:account)?[-_]key|AccountKey)[=:\s]+['\"]?([A-Za-z0-9+/=]{88})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Terraform_Cloud_Token",
			Regex:    regexp.MustCompile(`(?i)(?:TF_API_TOKEN|TERRAFORM_TOKEN|tfc[-_])[=:\s]+['\"]?([A-Za-z0-9_-]{36,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Ansible_Vault_Password",
			Regex:    regexp.MustCompile(`(?i)ANSIBLE_VAULT_PASSWORD[=:\s]+['\"]?([^\s'\"]+)`),
			Severity: "Critical",
		},
		{
			Name:     "Grafana_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:grafana|GRAFANA)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9_-]{24,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "SonarQube_Token",
			Regex:    regexp.MustCompile(`(?i)(?:sonar|SONAR)[-_]?(?:token|login|key)[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "CircleCI_Token",
			Regex:    regexp.MustCompile(`(?i)(?:CIRCLE_CI|circleci)[-_]?(?:token|api)[=:\s]+['\"]?([A-Za-z0-9]{40})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "TravisCI_API_Token",
			Regex:    regexp.MustCompile(`(?i)(?:TRAVIS_CI|travis)[-_]?(?:api_?)?token[=:\s]+['\"]?([A-Za-z0-9]{22,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Buildkite_Agent_Token",
			Regex:    regexp.MustCompile(`(?i)BUILDKITE_AGENT_TOKEN[=:\s]+['\"]?([A-Za-z0-9_-]{24,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Jenkins_API_Token",
			Regex:    regexp.MustCompile(`(?i)JENKINS[-_](?:API_?)?TOKEN[=:\s]+['\"]?([A-Za-z0-9]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Docker_Config_Auth",
			Regex:    regexp.MustCompile(`"auth"\s*:\s*"([A-Za-z0-9+/=]{40,})"`),
			Severity: "Critical",
		},
		{
			Name:     "npm_Auth_Token",
			Regex:    regexp.MustCompile(`//registry\.npmjs\.org/:_authToken[=:]\s*([A-Za-z0-9_-]{36,})`),
			Severity: "Critical",
		},
		{
			Name:     "Azure_DevOps_PAT",
			Regex:    regexp.MustCompile(`(?i)AZURE_DEVOPS_(?:EXT_)?PAT[=:\s]+['\"]?([A-Za-z0-9]{52})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Railway_API_Token",
			Regex:    regexp.MustCompile(`(?i)(?:RAILWAY|railway)[-_]?(?:api_?)?(?:token|key)[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Render_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:RENDER|render)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Fly_API_Token",
			Regex:    regexp.MustCompile(`(?i)(?:FLY_?API_?TOKEN|FLY_?ACCESS_?TOKEN)[=:\s]+['\"]?([A-Za-z0-9_-]{30,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Vultr_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:VULTR|vultr)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9]{36,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Hetzner_API_Token",
			Regex:    regexp.MustCompile(`(?i)(?:HETZNER|hetzner)[-_]?(?:api_?)?token[=:\s]+['\"]?([A-Za-z0-9_-]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Scaleway_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:SCALEWAY|scaleway)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "OVH_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:OVH|ovh)[-_]?(?:api|application)[-_]?key[=:\s]+['\"]?([A-Za-z0-9]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Linode_API_Token",
			Regex:    regexp.MustCompile(`(?i)(?:LINODE|linode)[-_]?(?:api_?)?token[=:\s]+['\"]?([A-Za-z0-9]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "IBM_Cloud_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:IBM_CLOUD|ibmcloud)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},

		// ==================== 社交 / 媒体平台 ====================
		{
			Name:     "Discord_Bot_Token",
			Regex:    regexp.MustCompile(`[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}`),
			Severity: "Critical",
		},
		{
			Name:     "Google_Maps_API_Key",
			Regex:    regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
			Severity: "High",
		},
		{
			Name:     "Google_OAuth_Client_Secret",
			Regex:    regexp.MustCompile(`(?i)GOOGLE[-_]?(?:OAUTH_)?CLIENT_SECRET[=:\s]+['\"]?([A-Za-z0-9_-]{24,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Facebook_App_Secret",
			Regex:    regexp.MustCompile(`(?i)FACEBOOK[-_]?(?:APP_)?SECRET[=:\s]+['\"]?([A-Za-z0-9]{32})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Twitter_API_Key",
			Regex:    regexp.MustCompile(`(?i)TWITTER[-_](?:API_?)?(?:KEY|SECRET)[=:\s]+['\"]?([A-Za-z0-9_-]{25,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Spotify_Client_Secret",
			Regex:    regexp.MustCompile(`(?i)SPOTIFY[-_]?(?:CLIENT_)?SECRET[=:\s]+['\"]?([A-Za-z0-9]{32})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Dropbox_Access_Token",
			Regex:    regexp.MustCompile(`(?i)(?:sl\.|DROPBOX_ACCESS_TOKEN)[A-Za-z0-9_-]{40,}`),
			Severity: "Critical",
		},
		{
			Name:     "HubSpot_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:HUBSPOT|hubspot)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9_-]{36,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Mailgun_API_Key",
			Regex:    regexp.MustCompile(`(?i)key-[A-Za-z0-9]{32}`),
			Severity: "Critical",
		},
		{
			Name:     "Mailchimp_API_Key",
			Regex:    regexp.MustCompile(`[A-Za-z0-9]{32}-us[0-9]{1,2}`),
			Severity: "Critical",
		},
		{
			Name:     "Zendesk_API_Token",
			Regex:    regexp.MustCompile(`(?i)ZENDESK[-_]?(?:API_?)?TOKEN[=:\s]+['\"]?([A-Za-z0-9]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Intercom_API_Token",
			Regex:    regexp.MustCompile(`(?i)INTERCOM[-_]?(?:API_?)?TOKEN[=:\s]+['\"]?([A-Za-z0-9]{60,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Jira_API_Token",
			Regex:    regexp.MustCompile(`(?i)JIRA[-_]?(?:API_?)?TOKEN[=:\s]+['\"]?([A-Za-z0-9]{24,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Contentful_CMA_Token",
			Regex:    regexp.MustCompile(`CFPAT-[A-Za-z0-9]{32,}`),
			Severity: "Critical",
		},
		{
			Name:     "Hasura_Admin_Secret",
			Regex:    regexp.MustCompile(`(?i)HASURA_GRAPHQL_ADMIN_SECRET[=:\s]+['\"]?([A-Za-z0-9_-]{16,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Strapi_Admin_JWT",
			Regex:    regexp.MustCompile(`(?i)STRAPI_ADMIN_JWT[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Sanity_API_Token",
			Regex:    regexp.MustCompile(`(?i)sk[A-Za-z0-9]{40,}`),
			Severity: "Critical",
		},
		{
			Name:     "Webflow_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:WEBFLOW|webflow)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9_-]{30,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Wix_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:WIX|wix)[-_]?(?:api_?)?key[=:\s]+['\"]?([A-Za-z0-9_-]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "BigCommerce_API_Token",
			Regex:    regexp.MustCompile(`(?i)(?:BIGCOMMERCE|bigcommerce)[-_]?(?:api_?)?(?:token|key)[=:\s]+['\"]?([A-Za-z0-9]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "WooCommerce_API_Key",
			Regex:    regexp.MustCompile(`(?i)ck_[A-Za-z0-9]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "Magento_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:MAGENTO|magento)[-_]?(?:api_?)?(?:key|token)[=:\s]+['\"]?([A-Za-z0-9]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Salesforce_Consumer_Secret",
			Regex:    regexp.MustCompile(`(?i)SALESFORCE[-_]CONSUMER_SECRET[=:\s]+['\"]?([A-Za-z0-9]{32,})['\"]?`),
			Severity: "Critical",
		},

		// ==================== 测试 / 浏览器自动化 ====================
		{
			Name:     "BrowserStack_Access_Key",
			Regex:    regexp.MustCompile(`(?i)BROWSERSTACK[-_]ACCESS[-_]KEY[=:\s]+['\"]?([A-Za-z0-9]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "SauceLabs_API_Key",
			Regex:    regexp.MustCompile(`(?i)SAUCE[-_]?(?:LABS_)?(?:API_?)?(?:KEY|ACCESS_KEY)[=:\s]+['\"]?([A-Za-z0-9-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Cypress_Record_Key",
			Regex:    regexp.MustCompile(`(?i)CYPRESS[-_]RECORD[-_]KEY[=:\s]+['\"]?([A-Za-z0-9_-]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Bitrise_API_Token",
			Regex:    regexp.MustCompile(`(?i)BITRISE[-_]?(?:API_?)?TOKEN[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "AppCenter_API_Token",
			Regex:    regexp.MustCompile(`(?i)APPCENTER[-_]?(?:API_?)?TOKEN[=:\s]+['\"]?([A-Za-z0-9]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Postman_API_Key",
			Regex:    regexp.MustCompile(`(?i)PMAK-[A-Za-z0-9_-]{32,}`),
			Severity: "Critical",
		},
		{
			Name:     "Insomnia_API_Key",
			Regex:    regexp.MustCompile(`(?i)INSOMNIA[-_]?(?:API_?)?KEY[=:\s]+['\"]?([A-Za-z0-9]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "ClickUp_API_Key",
			Regex:    regexp.MustCompile(`(?i)CLICKUP[-_]?(?:API_?)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{32,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Asana_PAT",
			Regex:    regexp.MustCompile(`(?i)ASANA[-_]?(?:PERSONAL_)?ACCESS_TOKEN[=:\s]+['\"]?([0-9]+/[0-9a-f]{32})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Monday_API_Key",
			Regex:    regexp.MustCompile(`(?i)MONDAY[-_]?(?:API_?)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Trello_API_Key",
			Regex:    regexp.MustCompile(`(?i)TRELLO[-_]?(?:API_?)?KEY[=:\s]+['\"]?([A-Za-z0-9]{32})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Linear_API_Key",
			Regex:    regexp.MustCompile(`lin_api_[A-Za-z0-9_-]{40,}`),
			Severity: "Critical",
		},
		{
			Name:     "Notion_Integration_Token",
			Regex:    regexp.MustCompile(`ntn_[A-Za-z0-9_-]{40,}`),
			Severity: "Critical",
		},
		{
			Name:     "GitBook_API_Token",
			Regex:    regexp.MustCompile(`(?i)GITBOOK[-_]?(?:API_?)?TOKEN[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Kubernetes_SA_Token",
			Regex:    regexp.MustCompile(`(?i)KUBERNETES[-_]?SERVICE_ACCOUNT_TOKEN[=:\s]+['\"]?([A-Za-z0-9_-]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Helm_Repo_Password",
			Regex:    regexp.MustCompile(`(?i)HELM_REPO_PASSWORD[=:\s]+['\"]?([^\s'\"]+)`),
			Severity: "High",
		},
		{
			Name:     "Apple_APNs_Key",
			Regex:    regexp.MustCompile(`(?i)APNS[-_]?(?:AUTH_)?KEY[=:\s]+['\"]?([A-Za-z0-9]{40,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "App_Store_Connect_API_Key",
			Regex:    regexp.MustCompile(`(?i)APP_STORE_CONNECT[-_]?(?:API_?)?KEY[=:\s]+['\"]?([A-Za-z0-9]{40,})['\"]?`),
			Severity: "Critical",
		},

		// ==================== 新增 / 通用综合模式 ====================
		{
			Name:     "Docker_Compose_Password",
			Regex:    regexp.MustCompile(`(?i)POSTGRES_PASSWORD[=:\s]+['\"]?([^\s'\"]{8,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Docker_Compose_Secret",
			Regex:    regexp.MustCompile(`(?i)(?:MYSQL|MARIADB|MONGO|REDIS)_(?:ROOT_)?PASSWORD[=:\s]+['\"]?([^\s'\"]{8,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Kubeconfig_User_Password",
			Regex:    regexp.MustCompile(`(?i)client-certificate-data:\s+([A-Za-z0-9+/=]{100,})`),
			Severity: "Critical",
		},
		{
			Name:     "Kubeconfig_Token",
			Regex:    regexp.MustCompile(`(?i)token:\s+([A-Za-z0-9_-]{40,})`),
			Severity: "Critical",
		},

		// ==================== AI Agent / AI 平台 API 密钥 ====================
		{
			Name:     "Hugging_Face_Token",
			Regex:    regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "Replicate_API_Token",
			Regex:    regexp.MustCompile(`r8_[A-Za-z0-9]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "Groq_API_Key",
			Regex:    regexp.MustCompile(`gsk_[A-Za-z0-9]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "Perplexity_API_Key",
			Regex:    regexp.MustCompile(`pplx-[A-Za-z0-9_-]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "Mistral_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:MISTRAL|mist_)[-=_\s]+['"]?([A-Za-z0-9]{20,})['"]?`),
			Severity: "Critical",
		},
		{
			Name:     "xAI_Grok_API_Key",
			Regex:    regexp.MustCompile(`(?i)xai[-_][A-Za-z0-9]{20,}`),
			Severity: "Critical",
		},
		{
			Name:     "DeepSeek_API_Key",
			Regex:    regexp.MustCompile(`(?i)DEEPSEEK[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Together_AI_API_Key",
			Regex:    regexp.MustCompile(`(?i)TOGETHER[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Fireworks_AI_API_Key",
			Regex:    regexp.MustCompile(`(?i)FIREWORKS[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "ElevenLabs_API_Key",
			Regex:    regexp.MustCompile(`(?i)ELEVENLABS[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "AssemblyAI_API_Key",
			Regex:    regexp.MustCompile(`(?i)ASSEMBLYAI[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Deepgram_API_Key",
			Regex:    regexp.MustCompile(`(?i)DEEPGRAM[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Weights_Biases_API_Key",
			Regex:    regexp.MustCompile(`(?i)WANDB[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Neptune_AI_API_Token",
			Regex:    regexp.MustCompile(`(?i)NEPTUNE[-_]?(?:API_)?TOKEN[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Comet_ML_API_Key",
			Regex:    regexp.MustCompile(`(?i)COMET[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "MLflow_Tracking_Token",
			Regex:    regexp.MustCompile(`(?i)MLFLOW[-_]TRACKING[-_]?(?:TOKEN|PASSWORD|URI)[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Prefect_API_Key",
			Regex:    regexp.MustCompile(`(?i)PREFECT[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Modal_Token_ID",
			Regex:    regexp.MustCompile(`(?i)MODAL[-_]TOKEN[-_]ID[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "BentoML_API_Key",
			Regex:    regexp.MustCompile(`(?i)BENTOML[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Stability_AI_API_Key",
			Regex:    regexp.MustCompile(`(?i)STABILITY[-_]?(?:AI_)?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "RunwayML_API_Key",
			Regex:    regexp.MustCompile(`(?i)RUNWAY[-_]?(?:ML_)?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "AI21_Labs_API_Key",
			Regex:    regexp.MustCompile(`(?i)AI21[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Writer_API_Key",
			Regex:    regexp.MustCompile(`(?i)WRITER[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Synthesia_API_Key",
			Regex:    regexp.MustCompile(`(?i)SYNTHESIA[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "HeyGen_API_Key",
			Regex:    regexp.MustCompile(`(?i)HEYGEN[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "PlayHT_API_Key",
			Regex:    regexp.MustCompile(`(?i)PLAY[-_\.]?HT[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "D_ID_API_Key",
			Regex:    regexp.MustCompile(`(?i)D[-_]ID[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "Scale_AI_API_Key",
			Regex:    regexp.MustCompile(`(?i)SCALE[-_]?(?:AI_)?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Labelbox_API_Key",
			Regex:    regexp.MustCompile(`(?i)LABELBOX[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "LangChain_API_Key",
			Regex:    regexp.MustCompile(`(?i)LANGCHAIN[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "LlamaIndex_API_Key",
			Regex:    regexp.MustCompile(`(?i)LLAMAINDEX[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "LiteLLM_API_Key",
			Regex:    regexp.MustCompile(`(?i)LITELLM[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "OpenAI_Organization_ID",
			Regex:    regexp.MustCompile(`(?i)OPENAI[-_]?(?:ORGANIZATION|ORG)[-=_\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Medium",
		},
		{
			Name:     "Anthropic_Organization_ID",
			Regex:    regexp.MustCompile(`(?i)ANTHROPIC[-_]?(?:ORGANIZATION|ORG)[-=_\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Medium",
		},
		{
			Name:     "Leonardo_AI_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:LEONARDO[-_]?(?:API_)?KEY|LEO[-_]?API[-_]?KEY)[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Ideogram_AI_API_Key",
			Regex:    regexp.MustCompile(`(?i)(?:IDEOGRAM[-_]?(?:API_)?KEY|IDEO[-_]?API[-_]?KEY)[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Mintlify_API_Key",
			Regex:    regexp.MustCompile(`(?i)MINTLIFY[-_]?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Augment_Code_API_Key",
			Regex:    regexp.MustCompile(`(?i)AUGMENT[-_]?(?:CODE[-_])?(?:API_)?KEY[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "Replit_API_Key",
			Regex:    regexp.MustCompile(`(?i)REPLIT[-_]?(?:API_)?(?:KEY|TOKEN)[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		{
			Name:     "AI_Provider_Generic_API_Key",
			Regex:    regexp.MustCompile(`(?i)^\s*(?:export\s+)?(?:OPENAI|ANTHROPIC|CLAUDE|COHERE|AI21|MISTRAL|DEEPSEEK|GROQ|PERPLEXITY|TOGETHER|FIREWORKS|REPLICATE|HUGGINGFACE|HUGGING_FACE|STABILITY|RUNWAYML|ELEVENLABS|ASSEMBLYAI|DEEPGRAM|WRITER|SYNTHESIA|HEYGEN|PLAYHT|D_ID|CODEIUM|TABNINE|SUPERMAVEN|CODY|COPILOT|CURSOR|WINDSURF|BITO|ASKCODI|CODEGPT|GEMINI|BLACKBOX|REPLIT|DEVIN|OPENHANDS|SWEEP|CODEX|VERCEL|BOLT|LOVABLE|LEONARDO|IDEOGRAM|FACTORY|CODESANDBOX|GITPOD|MINTLIFY|AUGMENT|MIDJOURNEY)[-_]?(?:API_)?(?:KEY|TOKEN|SECRET)[=:\s]+['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "Critical",
		},
		{
			Name:     "AI_Model_Provider_Key_Assignment",
			Regex:    regexp.MustCompile(`(?i)^\s*(?:export\s+)?(?:[A-Za-z0-9_]+_)?(?:API_KEY|API_TOKEN|API_SECRET|ACCESS_KEY|SECRET_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?`),
			Severity: "High",
		},
		}
	})
	return patterns
}

// maskValue 对发现的敏感值进行脱敏，保留前6后4字符
func maskValue(value string) string {
	value = strings.TrimSpace(value)
	// 去掉引号
	value = strings.Trim(value, `'"`)
	value = strings.Trim(value, "`")

	n := len(value)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	// 9-10 字符：没有足够的中段可以隐藏，只显示前6位
	if n <= 10 {
		return value[:6] + strings.Repeat("*", n-6)
	}
	return value[:6] + strings.Repeat("*", n-10) + value[n-4:]
}

// truncate 截断字符串到指定长度（考虑多字节字符）
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
