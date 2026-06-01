package filter

import "regexp"

// WeightedPattern pairs a compiled regexp with its risk weight and label.
type WeightedPattern struct {
	Re     *regexp.Regexp
	Weight int
	Label  string
}

func p(pattern string, weight int, label string) WeightedPattern {
	return WeightedPattern{
		Re:     regexp.MustCompile(`(?i)` + pattern),
		Weight: weight,
		Label:  label,
	}
}

// VPN and proxy promotion.
var VPNPatterns = []WeightedPattern{
	p(`\bvpn\b`, 15, "vpn"),
	p(`nordvpn|expressvpn|surfshark`, 20, "vpn_brand"),
	p(`\bпрокси\b`, 15, "proxy"),
	p(`обход.{0,10}блокировок`, 20, "bypass"),
	p(`анонимайзер`, 15, "anonymizer"),
	p(`скрыть.{0,5}ip`, 20, "hide_ip"),
	p(`\bproxy\b`, 15, "proxy_en"),
	p(`защищённ|безопасный интернет`, 10, "secure_web"),
}

// Phishing / channel-migration spam.
var PhishingPatterns = []WeightedPattern{
	p(`мы переезжаем`, 30, "migration"),
	p(`новый.{0,10}чат`, 25, "new_chat"),
	p(`переходите.{0,15}ссылк`, 25, "follow_link"),
	p(`срочно.{0,10}перейти`, 30, "urgent_link"),
	p(`новая.{0,5}ссылка`, 25, "new_link"),
	p(`канал.{0,10}переезжа`, 30, "channel_move"),
	p(`перенос.{0,10}канала`, 30, "channel_transfer"),
	p(`подписывайтесь.{0,20}нов`, 20, "subscribe_new"),
	p(`нажми.{0,10}здесь`, 20, "click_here"),
}

// Scam job / remote-work offers.
var ScamJobPatterns = []WeightedPattern{
	p(`удалён[кщ]а`, 15, "remote_work"),
	p(`без опыта`, 15, "no_experience"),
	p(`доход.{0,10}в день`, 20, "daily_income"),
	p(`пиши.{0,5}в\s+лс`, 20, "dm_me"),
	p(`напиши.{0,10}личку`, 20, "dm_me2"),
	p(`\bвакансия\b`, 10, "vacancy"),
	p(`зарабатывай`, 15, "earn"),
	p(`заработать`, 15, "earn_money"),
	p(`быстро.{0,10}заработать`, 20, "quick_earn"),
	p(`пассивный.{0,5}доход`, 20, "passive_income"),
	p(`работа.{0,10}дому`, 15, "wfh"),
	p(`\d+\s*[₽$€]\s*в\s*день`, 25, "money_per_day"),
	p(`предлагаю.{0,10}работу`, 20, "offering_job"),
	p(`ищу.{0,10}сотрудник`, 15, "hiring"),
	p(`партнёрство`, 10, "partnership"),
	p(`написать.{0,10}менеджер`, 15, "write_manager"),
	p(`нужны.{0,10}люди`, 20, "need_people"),
	p(`на.{0,10}халтурку`, 20, "odd_jobs"),
	p(`лёгкий.{0,10}онлайн.{0,5}доход`, 20, "easy_online_income"),
	p(`стабильно.{0,10}от.{0,10}\d+`, 15, "stable_from_amount"),
	p(`подойдёт.{0,10}новичкам`, 15, "for_beginners"),
	p(`работаешь.{0,10}когда.{0,10}удобно`, 15, "work_when_convenient"),
	p(`полностью.{0,10}легально`, 15, "fully_legal"),
	p(`хочешь.{0,10}денег`, 20, "want_money"),
	p(`пиши.{0,5}в\s+л_с`, 20, "write_ls"),
	p(`помогу.{0,10}финансами`, 20, "help_with_finances"),
	p(`есть.{0,10}темка`, 20, "have_topic"),
	p(`за пару.{0,10}часов`, 15, "few_hours"),
	p(`\d+к\s*в\s*день`, 25, "k_per_day"),

	// OCR / homoglyph amounts like "14O-23O$ в день" (Latin O as digit).
	p(`\d+[oоOО]\s*[-–]\s*\d+[oоOО0]*\s*[$₽€]\s*в\s*день`, 35, "homoglyph_money_daily"),
	p(`\d+\s*[$₽€]\s*\+\s*.{0,25}в\s*день`, 30, "money_plus_daily"),

	// "No fees from you" + daily-pay job spam.
	p(`без.{0,30}оплат.{0,25}с.{0,15}ваш`, 25, "no_payment_from_you"),
	p(`ставьте.{0,20}\+.{0,25}сюда|кидайте.{0,20}плюс`, 25, "plus_dm_cta"),
	p(`пиши\s*\+\s*сюда`, 30, "write_plus_here"),

	// Ukrainian job / housing scam templates.
	p(`не\s*віддалено`, 40, "ua_not_remote_spam"),
	p(`робота.{0,50}(?:з|\+).{0,25}(?:житл|прожив)|житл(?:о|а).{0,30}(?:надаєм|включен|надає)|вакансії.{0,25}з.{0,15}житл`, 30, "ua_job_housing"),
	p(`в\s*особист|в\s*дірект|особисті\s*повідомлен`, 25, "ua_write_dm"),
	p(`шукаєм.{0,40}(?:працівник|співробітник)|потрібн.{0,30}(?:співробітник|працівник)`, 25, "ua_hiring"),
	p(`допомог.{0,30}(?:з|зі)\s*документ`, 28, "ua_help_documents"),
	p(`зарплат[аи].{0,30}\d+.{0,15}\$.{0,20}тиждень|тиждень.{0,25}\+.{0,20}бонус`, 28, "weekly_usd_salary_spam"),
	p(`робот.{0,20}(?:в|з).{0,20}продаж`, 22, "sales_job_mention"),

	// Warehouse / shift pay spam.
	p(`приглашаем.{0,40}сотрудник.{0,50}склад|сотрудник.{0,40}на\s+склад`, 30, "warehouse_hiring"),
	p(`от\s*\d[\d\s]*₽.{0,25}за\s+смену|за\s+смену.{0,40}\d+.{0,20}₽`, 30, "shift_rub_spam"),

	// Vague "easy money" + daily.
	p(`имеешь.{0,25}пару.{0,20}часов|пару.{0,20}часов.{0,60}свободн`, 28, "free_hours_spam"),
	p(`пару.{0,20}часов.{0,80}(?:от\s*[\d.]+|каждый\s*день|[oоOО]{2,})`, 30, "free_hours_daily_money"),
	p(`каждый\s*день.{0,50}обращайся|обращайся.{0,60}каждый\s*день`, 22, "daily_money_contact"),
	p(`[oоOО]{3,}[рpPР]?\s*(?:каждый\s*день|твои)|\d+\s*[oоOО]{2,}[рpPР]?\s*твои`, 32, "homoglyph_rub_spam"),
	p(`несколько\s+часов.{0,60}[oоOО]{2,}`, 30, "hours_homoglyph_money"),

	// Odd jobs / "errands" without leaving home.
	p(`поручен.{0,25}на.{0,20}час`, 25, "errands_per_hour"),
	p(`без.{0,20}движен.{0,30}оклад`, 25, "no_movement_salary"),

	// Casual apartment / "man for an hour" micro-jobs (cash, vague DM).
	p(`нужен.{0,50}(?:муж|человек|парень|мужик).{0,25}на\s+час`, 30, "man_for_hour_hire"),
	p(`адекватн.{0,25}(?:муж|человек|парень).{0,25}на\s+час`, 30, "adequate_man_hour"),
	p(`задач.{0,35}по\s+квартир`, 28, "apartment_tasks"),
	p(`скину\s+\d{3,}|скину.{0,20}\d{3,}`, 28, "will_transfer_amount"),
	p(`наличкой|наличными|наличк[ауой]`, 22, "cash_payment_slang"),
	p(`скину\s+\d+.{0,50}налич|налич.{0,40}скину`, 32, "amount_cash_offer"),
	p(`пишите.{0,25}в\s+общем|буду\s+благодарн`, 24, "vague_dm_thanks"),
	p(`нужен.{0,80}квартир.{0,120}(?:скину|налич|пиш)`, 35, "apartment_cash_hire"),

	// Garage/yard cash-in-hand micro-jobs.
	p(`участк.{0,40}уборк.{0,30}гараж|уборк.{0,30}гараж.{0,50}\d+`, 28, "garage_cleanup_job"),
	p(`ответственн.{0,50}участк.{0,50}(?:уборк|покос|помощ)`, 30, "responsible_yard_job"),
	p(`покосить.{0,30}траву|газонокосилк`, 25, "lawn_mowing_job"),
	p(`на\s+карту.{0,25}\d+\s*р|переводом\s+на\s+карту`, 28, "card_transfer_pay"),
	p(`\d+.{0,15}р.{0,20}на\s+руки.{0,40}(?:л\s*с|личк)|на\s+руки.{0,30}(?:в\s*лс|писать)`, 30, "rub_cash_hands_ls"),
	p(`\d+\s*р\s*\+.{0,40}в\s*д[еe]нь|до\s*\d+\s*часов?.{0,15}в\s*д[еe]нь`, 32, "rub_plus_hours_daily"),

	// Fake driver licence / boating licence docs.
	p(`оформл(?:ение|лення).{0,40}водительск`, 30, "fake_driver_license"),
	p(`документ.{0,20}гимс|гимс.{0,25}[🚗⛵]|[🚗⛵].{0,20}гимс`, 30, "gims_docs_spam"),
	p(`официальн.{0,30}гибдд|через\s+гибдд`, 32, "gibdd_official_claim"),
	p(`без\s+сдачи\s+экзамен`, 35, "no_exam_license"),
	p(`помощь.{0,50}(?:получени|возврат).{0,40}прав|получени.{0,40}прав.{0,60}возврат`, 35, "license_rights_help"),
	p(`обращайтесь.{0,40}личн`, 25, "contact_in_dm"),

	// Caps-lock mass hiring + money.
	p(`нужны\s+люди.{0,150}(?:в\s*день|₽|\$|р\s*\+)`, 35, "need_people_money_combo"),
	p(`срочн.{0,15}нужн.{0,15}люд|нужн.{0,10}люд.{0,80}(?:подработк|ваканс|выплат)`, 30, "urgent_need_people"),
	p(`есть\s+шабашк|шабашк.{0,40}нужн.{0,15}люд`, 35, "odd_job_urgent_hire"),
	p(`расч[её]т.{0,20}(?:сразу\s+)?на\s+месте|на\s+руки.{0,40}срочност`, 30, "cash_on_site_job"),

	// Remote-work recruitment spam.
	p(`удалёнк[аи].{0,30}18\+|18\+.{0,40}тыс.{0,20}ежедневн`, 32, "remote_18_daily_pay"),
	p(`жду\s*["']?\+["']?\s*сюда|тыс\.?\s*ежедневн`, 28, "plus_here_daily_thousands"),
	p(`набор.{0,25}удалённ|удалённ.{0,30}работ.{0,60}(?:₽|руб|сутки)`, 30, "remote_hiring_spam"),
	p(`\d+[\d\s–-]*₽\s*в\s*сутки|от\s*\d+.{0,10}₽\s*в\s*сутки`, 30, "money_per_day_alt"),
	p(`возможность\s+дохода|занятость\s+\d[\d\s–-]*час`, 28, "income_opportunity_spam"),
	p(`с\s+телефона.{0,40}обучаем|обучаем.{0,40}пишите`, 25, "phone_train_dm"),

	// USDT buy/sell spam.
	p(`приобрету\s+usdt|usdt\s+trc\s*20|куплю\s+usdt`, 35, "usdt_buy_spam"),

	// Mission / task reward spam.
	p(`мис+и[йи].{0,40}наград.{0,30}(?:рубл|карточк)|наград.{0,30}\d+.{0,20}рубл`, 30, "mission_reward_spam"),

	// Flyer / street promo gigs.
	p(`раздач[уа].{0,25}листовок|листовок.{0,40}(?:метро|тц)|стоять\s+у\s+метро`, 28, "flyer_distribution_job"),
	p(`ищу\s+ребят.{0,40}раздач|платим\s+сразу`, 25, "hiring_flyer_paid"),

	// Greek / Latin homoglyph bait (mixed-script job spam).
	p(`[\x{0370}-\x{03FF}].{0,400}(?:₽|руб|карт|личн|вложен)`, 40, "greek_homoglyph_job"),
	p(`без\s+вложен.{0,60}напишит`, 28, "no_investment_dm"),
	p(`напишит[еъ].{0,25}["']?\+["']?.{0,30}личн`, 30, "write_plus_dm"),

	// Telegram mini-app / story spam links (t.me/m/...).
	p(`t\.me/m/[a-zA-Z0-9_-]+`, 30, "tme_m_path_spam"),

	// Work-from-home + daily income + 18+ + @contact.
	p(`работа\s+из\s+дома`, 28, "work_from_home"),
	p(`доход\s+от\s+\d+.{0,20}(?:р|₽).{0,15}в\s+день`, 30, "income_from_amount_daily"),
	p(`совершеннолетн|только\s+для.{0,15}18\+`, 22, "adults_only_job"),
	p(`(?:пишите|пиши|напиши).{0,40}@\w+`, 25, "write_to_username"),

	// Blunt money bait.
	p(`хочешь.{0,20}поднять.{0,15}бабок|поднять\s+бабок`, 35, "raise_money_bait"),
	p(`пиши\s+мне|пиши\s*-\s*мне`, 25, "write_me_dm"),

	// DPS radar / map app ads (often with attachment, little text).
	p(`дпс\s+радар|радар.{0,40}дпс|беслпатн.{0,25}дпс|бесплатн.{0,25}дпс\s+радар`, 32, "dps_radar_spam"),
	p(`показывает\s+где\s+стоят\s+пост|посты\s+на\s+карте`, 28, "police_posts_map"),

	// Vague "easy help" recruitment.
	p(`требуются\s+люди.{0,50}помощ|ничего\s+тяжелого.{0,50}вознагражден`, 30, "easy_help_reward"),
	p(`вознаграждение\s+достойн.{0,40}(?:обсудим|заинтерес)`, 25, "decent_reward_discuss"),

	// "Profitable business" DM bait.
	p(`прибыльн.{0,15}дело|есть\s+прибыльн`, 30, "profitable_deal_spam"),
}

// Ban-tier scams (weight ≥ default ban threshold 80 — one hit ⇒ ban).
var BanPatterns = []WeightedPattern{
	p(`подшабаш|подшабабаш|есть\s+шабашк|шабашк.{0,60}расч[её]т\s+сразу`, 85, "ban_odd_job_slang"),
	p(`приобрету\s+usdt\s+trc|usdt\s+trc\s*20.{0,40}курс`, 85, "ban_usdt_trc20_buy"),
	p(`наличными\s+на\s+руки.{0,60}отзовитесь\s+в\s+личку|отзовитесь\s+в\s+личку.{0,80}наличными\s+на\s+руки`, 85, "ban_cash_hands_dm"),
	p(`выгодные\s+условия\s+вознаграждения.{0,40}каждый\s+день\s+наличными`, 85, "ban_daily_cash_reward"),
	p(`купить\s+usdt\s+за\s+налич|usdt\s+за\s+наличн`, 85, "ban_usdt_cash"),
	p(`банкомат.{0,80}обмен|обмен.{0,40}usdt`, 85, "ban_usdt_atm_meetup"),
	p(`нужны\s+деньги.{0,60}стартуй`, 85, "ban_need_money_start"),
	p(`пиши\s+и\s+стартуй`, 85, "ban_write_and_start"),
	p(`гибдд.{0,120}без\s+сдачи\s+экзамен|без\s+сдачи\s+экзамен.{0,120}гибдд`, 85, "ban_gibdd_no_exam"),
}

// Generic spam call-to-action phrases.
var CTAPatterns = []WeightedPattern{
	p(`только сегодня`, 15, "only_today"),
	p(`осталось.{0,10}\d+.{0,10}мест`, 20, "limited_spots"),
	p(`ограниченное.{0,10}предложение`, 20, "limited_offer"),
	p(`не упусти`, 10, "dont_miss"),
	p(`пиши сейчас|напиши сейчас`, 15, "write_now"),
	p(`пишите`, 10, "write"),
	p(`успей.{0,15}записаться`, 15, "sign_up_now"),
	p(`бесплатно.{0,10}первым`, 15, "free_first"),
}

// Foreign invite links (t.me/+ or joinchat).
var InviteLinkRe = regexp.MustCompile(`(?i)t\.me/\+[a-zA-Z0-9_-]+|t\.me/joinchat/[a-zA-Z0-9_-]+`)

// Short/suspicious URL services.
var ShortURLHostRe = regexp.MustCompile(`(?i)^(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|rebrand\.ly|cutt\.ly|is\.gd|short\.io)$`)
