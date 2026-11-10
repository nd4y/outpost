import { OperationJournal, terminal } from "./journal.js";
const $ = (id) => document.getElementById(id);
const ID = /^[a-f0-9]{64}$/;
const words = {
  en: {
    skip: "Skip to content",
    tagline: "Know which backup you can recover.",
    language: "Language",
    title: "Backup control",
    intro: "Choose a node and domain to inspect copies or request an authorized operation.",
    scope: "Scope",
    tenant: "Tenant",
    node: "Node",
    domain: "Domain",
    refresh: "Refresh",
    moreNodes: "More nodes",
    coverage: "Copies",
    placement: "Placement",
    commands: "Operations",
    configuration: "Policy",
    activity: "Activity",
    evidenceHelp:
      "Backup creation, target readback and verified restore are separate observations. Unknown values are not zero.",
    externalCopies: "External target observations",
    externalAudit: "Scheduled verification",
    externalAuditObserved: "Audit observed",
    auditVerified: "Ciphertext verified",
    auditMissing: "Missing data",
    auditInvalid: "Invalid content",
    auditUnavailable: "Audit unavailable",
    auditStale: "Stale observation",
    externalHelp:
      "These are historical worker readbacks, not current cloud health. Repeated observations of the same target are not extra copies. No receipt means unknown, not absent.",
    observedComplete: "Complete at the recorded check time",
    unconfirmedCopy: "Completeness unconfirmed",
    externalUnknown: "This report has no external-copy observation support.",
    assignment: "Current placement",
    currentAssignment: "Assigned",
    historicalAssignment: "Historical or unknown",
    generations: "Generations",
    jobs: "Queue",
    commandResults: "Worker results",
    commandHelp:
      "Only current grants are offered. The worker checks its local policy again. Admission is not completion.",
    command: "Request an operation",
    kind: "Operation",
    generation: "Exact generation",
    job: "Job identifier",
    preset: "Local recovery preset",
    versions: "File-version identifiers, one per line (empty: whole generation)",
    permit: "Signed maintenance permit",
    reviewCommand: "Review operation",
    newCommand: "New operation",
    review: "Review",
    reviewHelp:
      "Check the exact scope and identifiers. A maintenance permit can authorize deletion; its signed limits and identifiers are shown below.",
    send: "Submit reviewed operation",
    cancelReview: "Return to editing",
    configHelp:
      "Owners can preview an already signed configuration. Signing keys stay outside the browser. Changes may cover other domains only if your owner scope permits them.",
    signedConfig: "Signed configuration",
    configFile: "Configuration file (up to 32 MiB)",
    preview: "Preview changes",
    apply: "Apply this preview",
    receiptHelp:
      "Keep the operation identifier. A lost reply does not mean failure. Read the receipt or retry the same request; do not create a replacement operation.",
    operationId: "Operation identifier",
    readReceipt: "Read receipt",
    resolutionTitle: "Abandon an unpublished request",
    resolutionHelp:
      "Only requests with no published effect are eligible. The original request and audit remain retained. This does not cancel work already published to a node.",
    reviewResolution: "Review abandonment",
    confirmResolution: "Confirm abandonment",
    resolutionReady:
      "Review the original request and the new resolution identifier before confirming.",
    resolutionUnavailable:
      "This request cannot be abandoned: publication is already recorded, the result is terminal, or its effect is unknown. Read its receipt and worker result.",
    resolutionDone:
      "The service confirmed abandonment before publication. The original request and audit remain retained.",
    audit: "Audit",
    loadAudit: "Load audit",
    more: "Next page",
    previous: "Previous page",
    privacy: "No backup content or decryption keys are sent to this interface.",
    loading: "Loading…",
    empty: "No records in this view.",
    unknown: "Unknown",
    choose: "Choose…",
    roles: "Roles",
    status: "State",
    sequence: "Sequence",
    created: "Backup created",
    verified: "Target readback",
    restored: "Verified restore",
    target: "Target",
    bytes: "Bytes",
    objects: "Objects",
    pinned: "Pinned",
    yes: "Yes",
    no: "No",
    metadata: "Metadata",
    verification: "Verification",
    observed: "Original observation",
    retrieved: "View retrieved",
    progress: "Measured progress",
    error: "Error",
    source: "Source",
    profile: "Profile",
    ingress: "Ingress",
    revision: "Revision",
    expires: "Expires",
    class: "Class",
    protocol: "Protocol",
    maxObject: "Maximum object bytes",
    holders: "Holders",
    transit: "Transit",
    targets: "External targets",
    routes: "Peer routes",
    cloudRoutes: "Upload routes",
    from: "From",
    to: "To",
    mode: "Mode",
    allowedClasses: "Allowed classes",
    repository: "Repository",
    epoch: "Writer epoch",
    digest: "Digest",
    sources: "Sources",
    nodes: "Nodes",
    space: "Space",
    logical: "Logical bytes",
    physical: "Physical bytes",
    free: "Free bytes",
    reserved: "Reserved bytes",
    accounted: "Accounted bytes",
    spaceScope: "Accounting scope",
    reportSequence: "Report sequence",
    inventory: "Inventory",
    reportAbsent: "No signed report is available for this scope. Coverage is unknown.",
    policyAbsent:
      "No usable policy view. Refresh or ask the owner to publish an authorized policy.",
    lastKnown: "Last known view only; current availability is unknown.",
    noCommands: "No current command grant for this role and scope.",
    chooseOperation: "Choose an available operation, then review its exact target.",
    noNodes:
      "No enrolled nodes in this scope. Ask the owner to enroll a node or choose another tenant.",
    pausedHelp:
      "Pause preserves backup data and pending intent. Resume continues work under current policy.",
    restoreHelp:
      "Restore the exact selected generation into the locally admitted preset. Empty file-version selection means the whole generation. Existing paths are not silently overwritten.",
    maintenanceHelp:
      "Maintenance may permanently delete data within its signed permit. Review the permit, target identifiers and limits before submission.",
    scrubHelp: "Scrub checks the selected generation. It does not prove plaintext recovery.",
    retryHelp: "Retry the named job under current policy. It does not renew expired authority.",
    reviewed: "Review ready. Nothing has been submitted.",
    admitted: "Receipt received. Check its state; admission does not mean execution.",
    uncertain:
      "Reply unavailable. Keep this operation identifier and read its receipt before retrying.",
    retry: "Retry same request",
    forget: "Remove completed local record",
    retained: "Operation records retained in this browser tab",
    stalePreview:
      "Policy changed. Preview the signed file again; no replacement operation was submitted.",
    pendingConfig: "Select the identical signed configuration file to retry this operation.",
    candidateRevision: "Candidate revision",
    capacity: "Capacity estimate",
    before: "Before",
    after: "After",
    change: "Change",
    details: "Details",
    receipt: "Receipt",
    workerResult: "Worker result",
    started: "Started",
    finished: "Finished",
    attempts: "Attempts",
    restoreResult: "Restore result",
    result: "Result",
    reason: "Reason",
    actor: "Actor",
    selectScope: "Select a node and domain.",
    sessionUnavailable:
      "Cannot load the authenticated session. Check the client certificate and reload.",
    newReady: "New operation draft. Review the identifiers before sending.",
    recordLimit:
      "The browser holds 16 operations. Remove a completed local record before submitting another.",
    storageError:
      "The browser cannot safely retain the operation. Enable local storage and Web Locks or free space. Keep the original operation identifier if another tab already sent it.",
    storageAfterReply:
      "The service returned a receipt, but the browser could not save it. Keep the original operation identifier and read its receipt; do not submit a replacement.",
    invalid: "Invalid input or response. Check the identifiers and signed file.",
    denied: "Access denied. Ask the owner to check this certificate's role and scope.",
    conflict:
      "State changed or operation conflicts. Refresh the view and read the existing receipt.",
    offline: "Connection unavailable or timed out. Check connectivity and retry.",
    busy: "The service is busy. Retry shortly; do not create a replacement operation.",
    unavailable: "Requested data is unavailable. Refresh or inspect the node's last report.",
    capacityError:
      "The service cannot admit more work within its capacity. Existing operations remain recorded.",
    cancelled: "The view changed. Load the new scope.",
    loaded: "View loaded. Observation timestamps below are not refreshed by reading them.",
    operationReused:
      "The same draft already has an operation identifier. Its original request will be reused.",
    configReady:
      "Preview verified by the service. Review the digest, revisions and changes before applying.",
    retainedFile: "Identical signed file required",
    revoked: "Revoked",
    ownerOnly: "Publishing configuration requires the owner role.",
    page: "Page",
    selectedGeneration: "Use this generation",
    reportState: "Report state",
    futureObservation: "Browser clock precedes the observation; age is unknown.",
    secondsOld: "seconds since observation",
    exactSelection: "The generation is explicit; the interface never substitutes the latest one.",
    refreshReceipt: "Refresh receipt",
    terminal: "Terminal receipt",
    noRestore: "No verified restore reported",
    recoveryScope: "Recovery selection",
    previewInvalidated: "Input or scope changed. Review again before submitting.",
    pending: "Result not confirmed",
    transport: "Transfer state",
  },
  ru: {
    skip: "Перейти к содержимому",
    tagline: "Знайте, из какой копии можно восстановиться.",
    language: "Язык",
    title: "Управление резервными копиями",
    intro: "Выберите ноду и домен, чтобы проверить копии или запросить разрешённую операцию.",
    scope: "Область",
    tenant: "Контур",
    node: "Нода",
    domain: "Домен",
    refresh: "Обновить",
    moreNodes: "Ещё ноды",
    coverage: "Копии",
    placement: "Размещение",
    commands: "Операции",
    configuration: "Политика",
    activity: "Журнал",
    evidenceHelp:
      "Создание копии, чтение из целевого хранилища и проверенное восстановление - разные наблюдения. Неизвестное значение не равно нулю.",
    externalCopies: "Наблюдения внешних копий",
    externalAudit: "Проверка по расписанию",
    externalAuditObserved: "Время наблюдения",
    auditVerified: "Шифротекст проверен",
    auditMissing: "Данные отсутствуют",
    auditInvalid: "Содержимое повреждено",
    auditUnavailable: "Проверка недоступна",
    auditStale: "Наблюдение устарело",
    externalHelp:
      "Это исторические проверки воркера, а не текущее здоровье облака. Повторные наблюдения одного назначения не увеличивают число копий. Нет квитанции - неизвестно, а не отсутствует.",
    observedComplete: "Полнота подтверждена в указанное время",
    unconfirmedCopy: "Полнота не подтверждена",
    externalUnknown: "Этот отчет не поддерживает наблюдения внешних копий.",
    assignment: "Текущее размещение",
    currentAssignment: "Назначено",
    historicalAssignment: "Историческое или неизвестное",
    generations: "Поколения",
    jobs: "Очередь",
    commandResults: "Результаты воркера",
    commandHelp:
      "Доступны только действующие полномочия. Воркер повторно проверяет локальную политику. Приём команды не означает её завершения.",
    command: "Запросить операцию",
    kind: "Операция",
    generation: "Точное поколение",
    job: "Идентификатор задания",
    preset: "Локальный профиль восстановления",
    versions: "Идентификаторы версий файлов, по одному в строке (пусто: всё поколение)",
    permit: "Подписанный допуск обслуживания",
    reviewCommand: "Проверить операцию",
    newCommand: "Новая операция",
    review: "Проверка",
    reviewHelp:
      "Проверьте точную область и идентификаторы. Допуск обслуживания может разрешать удаление; ниже показаны его подписанные ограничения и идентификаторы.",
    send: "Отправить проверенную операцию",
    cancelReview: "Вернуться к редактированию",
    configHelp:
      "Владелец может проверить уже подписанную конфигурацию. Ключи подписи остаются вне браузера. Изменения других доменов допустимы только в пределах полномочий владельца.",
    signedConfig: "Подписанная конфигурация",
    configFile: "Файл конфигурации (до 32 МиБ)",
    preview: "Просмотреть изменения",
    apply: "Применить этот вариант",
    receiptHelp:
      "Сохраните идентификатор операции. Потеря ответа не означает отказ. Прочитайте квитанцию или повторите тот же запрос; не создавайте замену с новым идентификатором.",
    operationId: "Идентификатор операции",
    readReceipt: "Прочитать квитанцию",
    resolutionTitle: "Отказ от неопубликованного запроса",
    resolutionHelp:
      "Допустимы только запросы без опубликованного эффекта. Исходный запрос и аудит сохраняются. Работа, уже опубликованная ноде, этим действием не отменяется.",
    reviewResolution: "Проверить возможность отказа",
    confirmResolution: "Подтвердить отказ",
    resolutionReady:
      "Перед подтверждением проверьте исходный запрос и новый идентификатор решения.",
    resolutionUnavailable:
      "Отказ недоступен: публикация уже зафиксирована, результат завершён или эффект неизвестен. Прочитайте квитанцию и результат воркера.",
    resolutionDone: "Сервис подтвердил отказ до публикации. Исходный запрос и аудит сохранены.",
    audit: "Аудит",
    loadAudit: "Загрузить аудит",
    more: "Следующая страница",
    previous: "Предыдущая страница",
    privacy: "Содержимое резервных копий и ключи расшифрования в этот интерфейс не передаются.",
    loading: "Загрузка…",
    empty: "В этом представлении нет записей.",
    unknown: "Неизвестно",
    choose: "Выберите…",
    roles: "Роли",
    status: "Состояние",
    sequence: "Номер",
    created: "Копия создана",
    verified: "Чтение из хранилища",
    restored: "Проверенное восстановление",
    target: "Назначение",
    bytes: "Байты",
    objects: "Объекты",
    pinned: "Закреплено",
    yes: "Да",
    no: "Нет",
    metadata: "Метаданные",
    verification: "Проверка",
    observed: "Исходное наблюдение",
    retrieved: "Представление получено",
    progress: "Измеренный прогресс",
    error: "Ошибка",
    source: "Источник",
    profile: "Профиль",
    ingress: "Приёмник",
    revision: "Ревизия",
    expires: "Срок действия",
    class: "Класс",
    protocol: "Протокол",
    maxObject: "Предельный размер объекта, байт",
    holders: "Держатели",
    transit: "Транзит",
    targets: "Внешние хранилища",
    routes: "Маршруты между нодами",
    cloudRoutes: "Маршруты выгрузки",
    from: "Откуда",
    to: "Куда",
    mode: "Режим",
    allowedClasses: "Разрешённые классы",
    repository: "Репозиторий",
    epoch: "Эпоха записи",
    digest: "Хеш",
    sources: "Источники",
    nodes: "Ноды",
    space: "Место",
    logical: "Логические байты",
    physical: "Физические байты",
    free: "Свободные байты",
    reserved: "Резерв, байт",
    accounted: "Учтённые байты",
    spaceScope: "Область учёта",
    reportSequence: "Номер отчёта",
    inventory: "Каталог",
    reportAbsent: "Подписанного отчёта для этой области нет. Наличие копий неизвестно.",
    policyAbsent:
      "Представление политики недоступно. Обновите данные или попросите владельца опубликовать разрешённую политику.",
    lastKnown: "Показано последнее известное состояние; текущая доступность неизвестна.",
    noCommands: "Для этой роли и области нет действующего допуска команд.",
    chooseOperation: "Выберите доступную операцию, затем проверьте её точный объект.",
    noNodes:
      "В этой области нет зарегистрированных нод. Попросите владельца зарегистрировать ноду или выберите другой контур.",
    pausedHelp:
      "Пауза сохраняет данные копий и запланированную работу. Возобновление продолжает работу по текущей политике.",
    restoreHelp:
      "Восстановление точного выбранного поколения в локально разрешённый профиль. Пустой список версий означает всё поколение. Существующие пути не перезаписываются молча.",
    maintenanceHelp:
      "Обслуживание может безвозвратно удалить данные в пределах подписанного допуска. Перед отправкой проверьте допуск, идентификаторы объектов и ограничения.",
    scrubHelp: "Проверка выбранного поколения. Она не доказывает восстановление открытых данных.",
    retryHelp:
      "Повтор указанного задания по текущей политике. Просроченные полномочия не продлеваются.",
    reviewed: "Вариант готов к проверке. Запрос ещё не отправлен.",
    admitted: "Квитанция получена. Проверьте её состояние: приём не означает выполнение.",
    uncertain:
      "Ответ недоступен. Сохраните идентификатор операции и прочитайте квитанцию перед повтором.",
    retry: "Повторить тот же запрос",
    forget: "Убрать завершённую локальную запись",
    retained: "Операции, сохранённые в этой вкладке",
    stalePreview:
      "Политика изменилась. Повторно проверьте подписанный файл; новая операция не отправлена.",
    pendingConfig: "Для повтора выберите тот же подписанный файл конфигурации.",
    candidateRevision: "Ревизия кандидата",
    capacity: "Оценка объёма",
    before: "Было",
    after: "Станет",
    change: "Изменение",
    details: "Подробности",
    receipt: "Квитанция",
    workerResult: "Результат воркера",
    started: "Начало",
    finished: "Завершение",
    attempts: "Попытки",
    restoreResult: "Результат восстановления",
    result: "Результат",
    reason: "Причина",
    actor: "Инициатор",
    selectScope: "Выберите ноду и домен.",
    sessionUnavailable:
      "Не удалось открыть сессию. Проверьте клиентский сертификат и перезагрузите страницу.",
    newReady: "Новый черновик операции. Проверьте идентификаторы перед отправкой.",
    recordLimit:
      "В браузере сохранено 16 операций. Уберите завершённую локальную запись перед отправкой новой.",
    storageError:
      "Браузер не может надёжно сохранить операцию. Разрешите local storage и Web Locks или освободите место. Сохраните исходный идентификатор, если другая вкладка уже отправила запрос.",
    storageAfterReply:
      "Сервис вернул квитанцию, но браузер не смог её сохранить. Сохраните исходный идентификатор и прочитайте квитанцию; не отправляйте новую операцию взамен.",
    invalid: "Некорректный ввод или ответ. Проверьте идентификаторы и подписанный файл.",
    denied: "Доступ запрещён. Попросите владельца проверить роль и область этого сертификата.",
    conflict:
      "Состояние изменилось или операция конфликтует. Обновите данные и прочитайте существующую квитанцию.",
    offline: "Связь недоступна или истекло время ожидания. Проверьте соединение и повторите.",
    busy: "Сервис занят. Повторите позже, сохранив идентификатор операции.",
    unavailable:
      "Запрошенные данные недоступны. Обновите сведения или проверьте последний отчёт ноды.",
    capacityError: "Недостаточно ёмкости для новой работы. Прежние операции сохранены.",
    cancelled: "Область изменилась. Загрузите новое представление.",
    loaded: "Представление загружено. Чтение не обновляет время исходных наблюдений.",
    operationReused: "У этого черновика уже есть идентификатор. Будет повторён исходный запрос.",
    configReady: "Сервис проверил вариант. Перед применением проверьте хеш, ревизии и изменения.",
    retainedFile: "Нужен тот же подписанный файл",
    revoked: "Отозвано",
    ownerOnly: "Публикация конфигурации требует роли владельца.",
    page: "Страница",
    selectedGeneration: "Выбрать это поколение",
    reportState: "Состояние отчёта",
    futureObservation: "Часы браузера отстают от наблюдения; возраст неизвестен.",
    secondsOld: "секунд после наблюдения",
    exactSelection: "Поколение указано явно; интерфейс не заменяет его последним.",
    refreshReceipt: "Обновить квитанцию",
    terminal: "Конечная квитанция",
    noRestore: "Проверенное восстановление не заявлено",
    recoveryScope: "Выбор восстановления",
    previewInvalidated: "Ввод или область изменились. Проверьте вариант перед отправкой.",
    pending: "Результат не подтверждён",
    transport: "Состояние передачи",
  },
};
const stateNames = {
  ru: {
    ACTIVE: "Действует",
    INACTIVE: "Не действует",
    FRESH: "Актуален на момент получения",
    CURRENT: "Актуален на момент получения",
    STALE: "Устарел",
    MISSING: "Отсутствует",
    UNKNOWN: "Неизвестно",
    UNAVAILABLE: "Недоступно",
    OBSERVED: "Наблюдалось",
    OBSERVED_COMPLETE: "Полнота подтверждена в указанное время",
    UNCONFIRMED: "Полнота не подтверждена",
    "full-target-readback": "Полное чтение назначения",
    "cached-target-readback": "Чтение с сохранением возраста прежних проверок",
    COMPLETE: "Завершено",
    ABANDONED: "Отказ до публикации",
    INCOMPLETE: "Не завершено",
    CORRUPT: "Повреждено",
    NONE: "Нет проверки",
    QUEUED: "В очереди",
    RUNNING: "Выполняется",
    RETRY_WAIT: "Ожидает повтора",
    BLOCKED: "Заблокировано",
    PAUSED: "Приостановлено",
    ADMITTED: "Принято",
    FAILED: "Отказ",
    CANCELLED: "Отменено",
    VERIFIED: "Проверено",
    trusted: "Доверенная",
    untrusted: "Недоверенная",
    external: "Внешнее хранилище",
    owner: "Владелец",
    operator: "Оператор",
    viewer: "Наблюдатель",
    recovery: "Восстановление",
    pause: "Приостановить",
    resume: "Возобновить",
    retry: "Повторить задание",
    scrub: "Проверить поколение",
    restore: "Восстановить",
    maintenance: "Обслуживание",
    retention: "Защита копий",
  },
  en: {
    ABANDONED: "Abandoned before publication",
    FRESH: "Fresh when retrieved",
    CURRENT: "Current when retrieved",
    pause: "Pause",
    resume: "Resume",
    retry: "Retry job",
    scrub: "Scrub generation",
    restore: "Restore",
    maintenance: "Maintenance",
    retention: "Retention protection",
  },
};
let lang = navigator.language.startsWith("ru") ? "ru" : "en";
try {
  if (["en", "ru"].includes(localStorage.getItem("outpost-language")))
    lang = localStorage.getItem("outpost-language");
} catch {
  /* Language preference is optional. */
}
const tr = (key) => words[lang][key] || words.en[key] || key;
const label = (value) => stateNames[lang][value] || value || tr("unknown");
const text = (value) =>
  value === null || value === undefined || value === "" ? tr("unknown") : String(value);
const date = (value) =>
  Number.isSafeInteger(value) && value > 0
    ? new Date(value * 1000).toLocaleString(lang, { timeZoneName: "short" })
    : tr("unknown");
const el = (tag, content, cls) => {
  const n = document.createElement(tag);
  if (content !== undefined) n.textContent = content;
  if (cls) n.className = cls;
  return n;
};
const state = {
  session: null,
  nodes: [],
  cursor: "",
  policy: null,
  report: null,
  retrieved: 0,
  epoch: 0,
  edit: 0,
  configEdit: 0,
  abort: null,
  journal: [],
  command: null,
  config: null,
  audit: null,
  auditCursor: "",
  busy: false,
  loading: false,
};
const scope = () => ({
  tenant: $("tenant").value,
  node: $("node").value,
  domain: $("domain").value,
});
const scopeKey = () => JSON.stringify(scope());
const nodePath = (s) => {
  if (!ID.test(s.tenant) || !ID.test(s.node)) throw new Error("INVALID");
  return `/api/v1/tenants/${s.tenant}/nodes/${s.node}`;
};
const domainPath = (s) => {
  if (!ID.test(s.domain)) throw new Error("INVALID");
  return `${nodePath(s)}/domains/${s.domain}`;
};
let journal;
function sessionValid(value) {
  return (
    value?.format === "outpost-management-session-1" &&
    ID.test(value.actor) &&
    Array.isArray(value.roles) &&
    Array.isArray(value.scopes) &&
    value.scopes.every((s) => ID.test(s.tenant) && ID.test(s.domain))
  );
}
function recordAllowed(record) {
  const session = state.session;
  if (!session || !session.roles.some((r) => ["owner", "operator", "recovery"].includes(r)))
    return false;
  const domains = record.type === "command" ? [record.domain] : record.accessDomains;
  return (
    Array.isArray(domains) &&
    domains.length > 0 &&
    domains.every((d) => session.scopes.some((s) => s.tenant === record.tenant && s.domain === d))
  );
}
async function currentAuthority(record) {
  const session = await api("/api/v1/session");
  const previous = state.session;
  if (!sessionValid(session) || session.actor !== previous.actor) {
    state.session = null;
    state.journal = [];
    resetView();
    throw new Error("DENIED");
  }
  state.session = session;
  if (
    JSON.stringify(previous.roles) !== JSON.stringify(session.roles) ||
    JSON.stringify(previous.scopes) !== JSON.stringify(session.scopes)
  ) {
    // Previously rendered grants and reports do not establish current access.
    resetView();
  }
  renderOperations();
  if (!recordAllowed(record)) throw new Error("DENIED");
  if (record.type === "config" && !session.roles.includes("owner")) throw new Error("DENIED");
  if (record.type === "command") {
    const roles = ["restore"].includes(record.body.kind)
      ? ["owner", "recovery"]
      : record.body.kind === "maintenance"
        ? ["owner"]
        : ["owner", "operator"];
    if (!session.roles.some((role) => roles.includes(role))) throw new Error("DENIED");
  }
}
function journalSnapshot() {
  if (state.storageInvalid || !journal) throw new Error("STORAGE");
  return journal.snapshot();
}
window.addEventListener("storage", (event) => {
  if (!journal || (event.key !== null && event.key !== journal.key)) return;
  try {
    journalSnapshot();
  } catch (e) {
    state.journal = [];
    state.storageInvalid = true;
    renderOperations();
    showError(e);
  }
});
function notice(key, level = "info") {
  state.noticeKey = key;
  state.noticeLevel = level;
  $("notice").textContent = tr(key);
  $("notice").dataset.level = level;
}
function showError(e) {
  const keys = {
    DENIED: "denied",
    CONFLICT: "conflict",
    CAPACITY: "capacityError",
    BUSY: "busy",
    UNAVAILABLE: "unavailable",
    INVALID: "invalid",
    STORAGE: "storageError",
    STORAGE_AFTER: "storageAfterReply",
    LIMIT: "recordLimit",
    OFFLINE: "offline",
    FILE: "pendingConfig",
  };
  notice(keys[e.message] || "invalid", "error");
}
function translate() {
  document.documentElement.lang = lang;
  $("language").value = lang;
  document.querySelectorAll("[data-i18n]").forEach((n) => {
    n.textContent = tr(n.dataset.i18n);
  });
  document.querySelector("nav").setAttribute("aria-label", tr("scope"));
  if (state.session)
    $("session").textContent = `${tr("roles")}: ${state.session.roles.map(label).join(", ")}`;
  for (const id of ["tenant", "node", "domain"])
    if ($(id).options.length) $(id).options[0].textContent = tr("choose");
  if (state.nodes.length)
    options(
      "node",
      state.nodes.map((n) => [
        n.node,
        `${n.node} · ${label(n.class)}${n.revoked ? ` · ${tr("revoked")}` : ""}`,
      ]),
      $("node").value,
    );
  renderPolicy();
  renderReport();
  renderOperations();
  renderAudit();
  commandFields();
  if (state.noticeKey) notice(state.noticeKey, state.noticeLevel);
}
async function api(path, options = {}) {
  const controller = new AbortController();
  const external = options.signal;
  const abort = () => controller.abort();
  external?.addEventListener("abort", abort, { once: true });
  if (external?.aborted) controller.abort();
  const timer = setTimeout(abort, 12000);
  try {
    const response = await fetch(path, {
      method: options.method || "GET",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
      headers: options.body ? { "Content-Type": "application/json", "X-Outpost-Request": "1" } : {},
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    if (!response.headers.get("content-type")?.startsWith("application/json"))
      throw new Error("INVALID");
    const reader = response.body.getReader();
    let size = 0;
    const chunks = [];
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 12 * 1024 * 1024) {
        await reader.cancel();
        throw new Error("INVALID");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    let result;
    try {
      result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new Error("INVALID");
    }
    if (!response.ok)
      throw new Error(
        ["DENIED", "CONFLICT", "CAPACITY", "BUSY", "UNAVAILABLE", "INVALID"].includes(result.code)
          ? result.code
          : "UNAVAILABLE",
      );
    if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("INVALID");
    return result;
  } catch (e) {
    if (e.name === "AbortError" || e instanceof TypeError) throw new Error("OFFLINE");
    throw e;
  } finally {
    clearTimeout(timer);
    external?.removeEventListener("abort", abort);
  }
}
function options(id, values, selected = "") {
  const input = $(id);
  input.replaceChildren(new Option(tr("choose"), ""));
  for (const [value, name] of values) input.add(new Option(name, value));
  if (values.some(([value]) => value === selected)) input.value = selected;
  input.disabled = values.length === 0;
}
function pairs(container, values) {
  const dl = el("dl");
  for (const [name, value] of values) {
    dl.append(el("dt", tr(name)), el("dd", text(value)));
  }
  container.append(dl);
}
function table(container, headers, rows, start = 0) {
  container.replaceChildren();
  if (!rows.length) {
    container.append(el("p", tr("empty"), "muted"));
    return;
  }
  const wrap = el("div", undefined, "table-wrap");
  wrap.tabIndex = 0;
  wrap.setAttribute("role", "region");
  wrap.setAttribute("aria-label", headers.map(tr).join(", "));
  const grid = el("table"),
    head = el("thead"),
    hr = el("tr");
  for (const title of headers) {
    const th = el("th", tr(title));
    th.scope = "col";
    hr.append(th);
  }
  head.append(hr);
  grid.append(head);
  const body = el("tbody");
  for (const row of rows.slice(start, start + 50)) {
    const line = el("tr");
    for (const value of row) {
      const cell = el("td");
      if (typeof value === "function") cell.append(value());
      else cell.textContent = text(value);
      line.append(cell);
    }
    body.append(line);
  }
  grid.append(body);
  wrap.append(grid);
  container.append(wrap);
  if (rows.length > 50) {
    const pager = el("div", undefined, "pager");
    const back = button("previous", () => table(container, headers, rows, start - 50));
    back.disabled = start === 0;
    const next = button("more", () => table(container, headers, rows, start + 50));
    next.disabled = start + 50 >= rows.length;
    pager.append(
      back,
      el("span", `${tr("page")} ${Math.floor(start / 50) + 1} / ${Math.ceil(rows.length / 50)}`),
      next,
    );
    container.append(pager);
  }
}
function button(key, action) {
  const b = el("button", tr(key));
  b.type = "button";
  b.addEventListener("click", () => Promise.resolve().then(action).catch(showError));
  return b;
}
function resetView() {
  state.loading = false;
  state.edit++;
  state.configEdit++;
  state.epoch++;
  state.abort?.abort();
  state.abort = new AbortController();
  state.policy = null;
  state.report = null;
  state.retrieved = 0;
  state.command = null;
  state.config = null;
  state.resolution = null;
  $("resolution-review").hidden = true;
  state.audit = null;
  state.auditCursor = "";
  $("command-review").hidden = true;
  $("config-preview").hidden = true;
  $("audit-more").hidden = true;
  $("receipt-result").textContent = "";
  for (const id of ["generation", "job", "preset", "versions", "permit", "config-file"])
    $(id).value = "";
  renderPolicy();
  renderReport();
  renderOperations();
  renderAudit();
}
async function loadSession() {
  notice("loading");
  try {
    const value = await api("/api/v1/session");
    if (!sessionValid(value)) throw new Error("INVALID");
    state.session = value;
    try {
      journal = new OperationJournal(value.actor, (records) => {
        state.journal = records;
        renderOperations();
      });
      state.storageInvalid = false;
      await journal.open();
    } catch {
      state.journal = [];
      state.storageInvalid = true;
    }
    const tenants = [...new Set(value.scopes.map((v) => v.tenant))].filter((v) => ID.test(v));
    options(
      "tenant",
      tenants.map((v) => [v, v]),
      tenants.length === 1 ? tenants[0] : "",
    );
    translate();
    if ($("tenant").value) await loadNodes();
    else notice("selectScope");
  } catch (e) {
    showError(e);
    $("session").textContent = tr("sessionUnavailable");
  }
}
async function loadNodes(more = false) {
  const tenant = $("tenant").value;
  if (!ID.test(tenant)) {
    resetView();
    return;
  }
  const oldNode = $("node").value;
  if (!more) {
    resetView();
    state.nodes = [];
    state.cursor = "";
    options("node", []);
    options("domain", []);
  }
  const epoch = state.epoch;
  notice("loading");
  try {
    const page = await api(
      `/api/v1/tenants/${tenant}/nodes?limit=32${more && state.cursor ? `&cursor=${encodeURIComponent(state.cursor)}` : ""}`,
      { signal: state.abort?.signal },
    );
    if (epoch !== state.epoch || tenant !== $("tenant").value) return;
    if (
      page.format !== "outpost-management-nodes-1" ||
      !Array.isArray(page.items) ||
      page.items.length > 32 ||
      page.items.some((n) => !ID.test(n.node) || !Array.isArray(n.domains))
    )
      throw new Error("INVALID");
    state.nodes = more ? [...state.nodes, ...page.items] : page.items;
    state.cursor = page.nextCursor || "";
    if (
      state.nodes.length > 128 ||
      new Set(state.nodes.map((n) => n.node)).size !== state.nodes.length
    )
      throw new Error("INVALID");
    options(
      "node",
      state.nodes.map((n) => [
        n.node,
        `${n.node} · ${label(n.class)}${n.revoked ? ` · ${tr("revoked")}` : ""}`,
      ]),
      oldNode || (state.nodes.length === 1 ? state.nodes[0].node : ""),
    );
    $("nodes-more").hidden = !state.cursor;
    if (!state.nodes.length) notice("noNodes");
    else if (!more) await selectNode();
    else notice("loaded");
  } catch (e) {
    if (epoch !== state.epoch) return;
    if (e.message === "CONFLICT") {
      state.cursor = "";
      $("nodes-more").hidden = true;
    }
    showError(e);
  }
}
async function selectNode() {
  resetView();
  const n = state.nodes.find((v) => v.node === $("node").value);
  const domains = n?.domains.filter((v) => ID.test(v)) || [];
  options(
    "domain",
    domains.map((v) => [v, v]),
    domains.length === 1 ? domains[0] : "",
  );
  if ($("domain").value) await loadDomain();
  else notice("selectScope");
}
async function loadDomain() {
  if (!ID.test($("node").value) || !ID.test($("domain").value)) {
    notice("selectScope");
    return;
  }
  const s = scope(),
    key = scopeKey();
  const epoch = ++state.epoch;
  state.edit++;
  state.configEdit++;
  state.loading = true;
  state.abort?.abort();
  state.abort = new AbortController();
  state.command = null;
  state.config = null;
  state.resolution = null;
  $("resolution-review").hidden = true;
  $("command-review").hidden = true;
  $("config-preview").hidden = true;
  $("command-fields").disabled = true;
  $("config-fields").disabled = true;
  notice("loading");
  let error = null;
  try {
    const p = await api(`${domainPath(s)}/policy`, { signal: state.abort.signal });
    if (epoch !== state.epoch || key !== scopeKey()) return;
    if (
      p.format !== "outpost-management-domain-policy-1" ||
      p.node !== s.node ||
      p.domain !== s.domain ||
      p.tenant !== s.tenant ||
      !Array.isArray(p.capabilities) ||
      !Array.isArray(p.nodes) ||
      !Array.isArray(p.sources) ||
      !Array.isArray(p.targets)
    )
      throw new Error("INVALID");
    state.policy = p;
  } catch (e) {
    if (epoch !== state.epoch) return;
    state.policy = null;
    error = e;
  }
  try {
    const r = await api(`${domainPath(s)}/report`, { signal: state.abort.signal });
    if (epoch !== state.epoch || key !== scopeKey()) return;
    if (
      r.node !== s.node ||
      r.domain !== s.domain ||
      r.tenant !== s.tenant ||
      !Array.isArray(r.generations) ||
      r.generations.length > 256 ||
      !Array.isArray(r.jobs) ||
      r.jobs.length > 4096 ||
      !/^outpost-management-report-view-[1-6]$/.test(r.format) ||
      (r.externalState !== undefined &&
        (!/^outpost-management-report-view-[56]$/.test(r.format) ||
          r.externalState !== "OBSERVED")) ||
      (r.externalCopies !== undefined &&
        (!Array.isArray(r.externalCopies) ||
          r.externalCopies.length > 4096 ||
          r.externalState !== "OBSERVED" ||
          r.externalCopies.some(
            (c) => !c || (c.audit !== undefined && !validExternalAudit(c, r)),
          ))) ||
      (r.format === "outpost-management-report-view-6" && !r.externalCopies?.some((c) => c.audit))
    )
      throw new Error("INVALID");
    state.report = r;
    state.retrieved = Date.now();
    state.reportOffline = false;
  } catch (e) {
    if (epoch !== state.epoch) return;
    state.reportOffline = true;
    if (e.message === "DENIED") state.report = null;
    if (e.message !== "UNAVAILABLE") error = e;
  }
  state.loading = false;
  renderPolicy();
  renderReport();
  renderOperations();
  if (error) showError(error);
  else notice("loaded");
}
function renderPolicy() {
  const p = state.policy,
    box = $("policy-details");
  box.replaceChildren();
  $("policy-state").textContent = p
    ? `${tr("status")}: ${label(p.configurationState)} · ${tr("revision")}: ${p.configurationRevision}`
    : tr("policyAbsent");
  $("config-fields").disabled =
    state.loading || !state.session?.roles.includes("owner") || !ID.test($("node").value);
  if (!p) {
    options("kind", []);
    $("command-fields").disabled = true;
    return;
  }
  pairs(box, [
    ["repository", p.repository],
    ["epoch", p.writerEpoch],
    ["digest", p.configurationDigest],
    ["expires", date(p.expiresUnix)],
    ["allowedClasses", p.placement.allowedClasses.map(label).join(", ")],
    ["holders", p.placement.holders.join(", ")],
    ["transit", (p.placement.transit || []).join(", ")],
  ]);
  for (const [title, headers, rows] of [
    [
      "sources",
      ["source", "profile", "ingress", "revision", "status", "expires"],
      p.sources.map((s) => [
        s.node,
        s.profile,
        s.ingress,
        s.revision,
        label(s.state),
        date(s.expiresUnix),
      ]),
    ],
    ["nodes", ["node", "class"], p.nodes.map((n) => [n.id, label(n.class)])],
    [
      "targets",
      ["target", "protocol", "maxObject"],
      p.targets.map((t) => [t.id, t.kind, t.maxObjectBytes]),
    ],
    [
      "routes",
      ["from", "to", "mode"],
      (p.placement.edges || []).map((e) => [e.from, e.to, e.mode]),
    ],
    [
      "cloudRoutes",
      ["node", "target"],
      (p.placement.cloudEdges || []).map((e) => [e.node, e.target]),
    ],
  ]) {
    box.append(el("h3", tr(title)));
    const div = el("div");
    table(div, headers, rows);
    box.append(div);
  }
  const kinds = [
    ...new Set(
      p.capabilities
        .filter((c) => c.expiresUnix > Math.floor(Date.now() / 1000))
        .flatMap((c) => c.kinds),
    ),
  ].filter((k) => ["pause", "resume", "retry", "scrub", "restore", "maintenance"].includes(k));
  options(
    "kind",
    kinds.map((k) => [k, label(k)]),
    $("kind").value,
  );
  $("command-fields").disabled = state.loading || !kinds.length;
  commandFields();
}
const externalAuditLabels = new Map([
  ["VERIFIED_CIPHERTEXT", "auditVerified"],
  ["MISSING", "auditMissing"],
  ["INVALID_CONTENT", "auditInvalid"],
  ["UNAVAILABLE", "auditUnavailable"],
]);

function validExternalAudit(copy, report) {
  const a = copy.audit;
  return (
    report.format === "outpost-management-report-view-6" &&
    copy.state === "OBSERVED_COMPLETE" &&
    a &&
    externalAuditLabels.has(a.state) &&
    [a.observedUnix, a.finishedUnix, a.expiresUnix].every(Number.isSafeInteger) &&
    a.observedUnix > 0 &&
    a.observedUnix >= copy.verifiedUnix &&
    a.finishedUnix >= a.observedUnix &&
    a.finishedUnix <= report.observedUnix &&
    a.expiresUnix > a.observedUnix &&
    a.expiresUnix - a.observedUnix <= 2592000 &&
    (a.state === "VERIFIED_CIPHERTEXT" || a.observedUnix === a.finishedUnix)
  );
}

function externalAuditLabel(audit, report) {
  if (!audit) return tr("unknown");
  const state = tr(externalAuditLabels.get(audit.state));
  const stale = report.state === "STALE" || Date.now() >= audit.expiresUnix * 1000;
  return stale ? `${tr("auditStale")} · ${state}` : state;
}

function renderExternalCopies() {
  const report = state.report;
  const supported = report?.externalState === "OBSERVED";
  $("external-state").textContent = supported ? tr("externalHelp") : tr("externalUnknown");
  const desired = new Set((state.policy?.targets || []).map((t) => t.id));
  const observations = supported ? report.externalCopies || [] : [];
  const seen = new Set(observations.map((c) => c.target));
  const rows = observations.map((c) => [
    c.target,
    c.generation,
    c.state === "OBSERVED_COMPLETE"
      ? tr("observedComplete")
      : c.state === "UNCONFIRMED"
        ? tr("unconfirmedCopy")
        : label(c.state),
    label(c.verification),
    date(c.verifiedUnix),
    c.operationId,
    desired.has(c.target) ? tr("currentAssignment") : tr("historicalAssignment"),
    c.errorCode || "-",
    externalAuditLabel(c.audit, report),
    date(c.audit?.observedUnix),
  ]);
  for (const target of desired)
    if (!seen.has(target))
      rows.push([
        target,
        null,
        tr("unknown"),
        tr("unknown"),
        tr("unknown"),
        null,
        tr("currentAssignment"),
        "-",
        tr("unknown"),
        tr("unknown"),
      ]);
  table(
    $("external-copies"),
    [
      "target",
      "generation",
      "status",
      "verification",
      "verified",
      "operationId",
      "assignment",
      "error",
      "externalAudit",
      "externalAuditObserved",
    ],
    rows,
  );
}
function renderReport() {
  const r = state.report;
  $("report-state").textContent = r
    ? `${tr("reportState")}: ${label(r.state)}${state.reportOffline ? ` · ${tr("lastKnown")}` : ""}`
    : tr("reportAbsent");
  $("report-age").textContent = r
    ? `${tr("observed")}: ${date(r.observedUnix)} · ${tr("retrieved")}: ${date(Math.floor(state.retrieved / 1000))} · ${tr("reportSequence")}: ${r.sequence} · ${tr("inventory")}: ${label(r.inventoryState)}`
    : "";
  $("space").replaceChildren();
  $("generation-list").replaceChildren();
  for (const id of ["generations", "jobs", "command-results"]) $(id).replaceChildren();
  renderExternalCopies();
  if (!r) return;
  const s = r.space || {};
  pairs($("space"), [
    ["space", label(s.state)],
    ["spaceScope", s.scope],
    ["accounted", s.accountedBytes],
    ["logical", s.logicalBytes],
    ["physical", s.physicalBytes],
    ["free", s.freeBytes],
    ["reserved", s.reservedBytes],
    ["observed", date(s.observedUnix)],
  ]);
  for (const g of r.generations)
    if (ID.test(g.generation)) $("generation-list").append(new Option(g.generation, g.generation));
  table(
    $("generations"),
    [
      "generation",
      "target",
      "status",
      "created",
      "verification",
      "verified",
      "restored",
      "metadata",
      "objects",
      "bytes",
      "pinned",
      "recoveryScope",
    ],
    r.generations.map((g) => [
      g.generation,
      g.target,
      label(g.status),
      date(g.createdUnix),
      label(g.verification),
      date(g.verifiedUnix),
      g.restoreVerifiedUnix ? date(g.restoreVerifiedUnix) : tr("noRestore"),
      label(g.metadataState || "OBSERVED"),
      g.metadataState === "UNAVAILABLE" ? tr("unknown") : g.objects,
      g.logicalBytes,
      tr(g.pinned ? "yes" : "no"),
      () => {
        const b = button("selectedGeneration", () => {
          $("generation").value = g.generation;
          invalidateCommand();
          $("commands").scrollIntoView();
          $("generation").focus();
        });
        b.disabled = $("command-fields").disabled;
        return b;
      },
    ]),
  );
  table(
    $("jobs"),
    ["operationId", "kind", "generation", "status", "progress", "observed", "error"],
    r.jobs.map((j) => [
      j.operationId,
      label(j.kind),
      j.generation,
      label(j.phase),
      `${text(j.completedBytes)} / ${text(j.totalBytes)} ${tr("bytes")}`,
      date(j.updatedUnix),
      j.errorCode || "-",
    ]),
  );
  table(
    $("command-results"),
    [
      "operationId",
      "kind",
      "status",
      "generation",
      "progress",
      "started",
      "finished",
      "attempts",
      "error",
      "details",
    ],
    (r.commands || []).map((c) => [
      c.operationId,
      label(c.kind),
      label(c.phase),
      c.generation,
      `${c.verifiedObjects} / ${c.totalObjects}`,
      date(c.startedUnix),
      date(c.finishedUnix),
      c.attempts,
      c.errorCode || "-",
      () => {
        const d = el("details");
        d.append(el("summary", tr("workerResult")), el("pre", JSON.stringify(c, null, 2)));
        return d;
      },
    ]),
  );
}
function commandFields() {
  const kind = $("kind").value;
  for (const [id, enabled, required] of [
    ["generation", ["scrub", "restore"].includes(kind), true],
    ["job", ["retry", "pause", "resume"].includes(kind), kind === "retry"],
    ["preset", kind === "restore", true],
    ["versions", kind === "restore", false],
    ["permit", kind === "maintenance", true],
  ]) {
    $(id).disabled = !enabled;
    $(id).required = enabled && required;
  }
  $("command-consequence").textContent = tr(
    !kind
      ? $("kind").options.length > 1
        ? "chooseOperation"
        : "noCommands"
      : kind === "restore"
        ? "restoreHelp"
        : kind === "maintenance"
          ? "maintenanceHelp"
          : kind === "scrub"
            ? "scrubHelp"
            : kind === "retry"
              ? "retryHelp"
              : "pausedHelp",
  );
}
function invalidateCommand() {
  state.edit++;
  state.command = null;
  $("command-review").hidden = true;
}
async function hash(value) {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        typeof value === "string" ? new TextEncoder().encode(value) : value,
      ),
    ),
    (v) => v.toString(16).padStart(2, "0"),
  ).join("");
}
const newID = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(32)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
function base64(bytes) {
  let value = "";
  for (let i = 0; i < bytes.length; i += 16384)
    value += String.fromCharCode(...bytes.subarray(i, i + 16384));
  return btoa(value);
}
async function fileBytes(input, max) {
  const file = $(input).files[0];
  if (!file || file.size === 0 || file.size > max) throw new Error("INVALID");
  return new Uint8Array(await file.arrayBuffer());
}
async function reviewCommand() {
  const edit = state.edit;
  const s = scope(),
    key = scopeKey(),
    p = state.policy,
    kind = $("kind").value;
  if (!p || p.configurationState !== "ACTIVE") throw new Error("DENIED");
  const capability = p.capabilities.find(
    (c) => c.kinds.includes(kind) && c.expiresUnix > Math.floor(Date.now() / 1000) + 5,
  );
  if (!capability) throw new Error("DENIED");
  const body = {
    reason: kind === "maintenance" ? "OWNER_MAINTENANCE" : "OPERATOR_REQUEST",
    tenant: s.tenant,
    domain: s.domain,
    kind,
    expectedConfigurationRevision: p.configurationRevision,
  };
  for (const id of ["generation", "job", "preset"])
    if (!$(id).disabled && $(id).value) {
      if (!ID.test($(id).value)) throw new Error("INVALID");
      body[id] = $(id).value;
    }
  if (kind === "restore") {
    const versions = $("versions").value.trim().split(/\s+/).filter(Boolean);
    if (
      versions.length > 256 ||
      versions.some((v) => !ID.test(v)) ||
      new Set(versions).size !== versions.length
    )
      throw new Error("INVALID");
    if (versions.length) body.versions = versions;
  }
  let permitView = null;
  if (kind === "maintenance") {
    const bytes = await fileBytes("permit", 1 << 20);
    try {
      permitView = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new Error("INVALID");
    }
    body.maintenancePermit = base64(bytes);
  }
  const fingerprint = await hash(JSON.stringify({ node: s.node, ...body }));
  const snapshot = journalSnapshot();
  const latest = snapshot.records.findLast(
    (r) => r.type === "command" && r.fingerprint === fingerprint,
  );
  const existing =
    latest && !(terminal(latest) && state.newAfter === latest.operation) ? latest : null;
  const record = existing || {
    ...s,
    type: "command",
    operation: newID(),
    fingerprint,
    journalRevision: snapshot.revision,
    basedOn: latest?.operation,
    body: {
      ...body,
      operationId: "",
      authority: capability.authority,
      expiresUnix: Math.min(capability.expiresUnix, Math.floor(Date.now() / 1000) + 3600),
    },
  };
  if (!existing) record.body.operationId = record.operation;
  if (key !== scopeKey() || edit !== state.edit) return;
  state.command = record;
  $("command-summary").textContent = JSON.stringify(
    {
      tenant: record.tenant,
      node: record.node,
      domain: record.domain,
      operationId: record.operation,
      ...body,
      expires: date(record.body.expiresUnix),
      ...(permitView ? { signedMaintenancePermit: permitView } : {}),
    },
    (k, v) => (k === "authority" || k === "maintenancePermit" ? undefined : v),
    2,
  );
  $("command-review").hidden = false;
  $("send-command").focus();
  notice(existing ? "operationReused" : "reviewed");
}
async function submit(record, configBody) {
  if (state.busy) return;
  state.busy = true;
  $("send-command").disabled = true;
  $("apply-config").disabled = true;
  try {
    await journal.dispatch(async () => {
      if (state.storageInvalid) throw new Error("STORAGE");
      await currentAuthority(record);
      if (record.type === "config" && (!configBody || configBody.previewDigest !== record.digest))
        throw new Error("FILE");
      record = await journal.admit(record); // Shared durable request precedes every remote effect.
      await currentAuthority(record);
      const body =
        record.type === "command"
          ? record.body
          : { ...configBody, operationId: record.operation, expectedRevision: record.expected };
      if (!body || body.operationId !== record.operation) throw new Error("FILE");
      if (
        record.type === "command" &&
        scopeKey() ===
          JSON.stringify({ tenant: record.tenant, node: record.node, domain: record.domain })
      )
        state.command = record;
      let result;
      try {
        result = await api(
          `${nodePath(record)}/${record.type === "command" ? "commands" : "configuration"}`,
          { method: record.type === "command" ? "POST" : "PUT", body },
        );
      } catch (e) {
        if (e.message === "OFFLINE" || e.message === "UNAVAILABLE") notice("uncertain", "error");
        else showError(e);
        return;
      }
      if (result.operationId !== record.operation) throw new Error("INVALID");
      try {
        await journal.receipt(record.operation, result);
      } catch {
        throw new Error("STORAGE_AFTER");
      }
      notice("admitted");
    });
  } finally {
    state.busy = false;
    $("send-command").disabled = false;
    $("apply-config").disabled = false;
  }
}
async function previewConfig() {
  const edit = state.configEdit;
  if (!state.session?.roles.includes("owner")) throw new Error("DENIED");
  const s = scope(),
    key = scopeKey(),
    file = await fileBytes("config-file", 32 << 20),
    digest = await hash(file);
  const expected = state.policy?.configurationRevision || 0;
  const fingerprint = await hash(JSON.stringify({ tenant: s.tenant, node: s.node, digest }));
  const snapshot = journalSnapshot();
  const old = snapshot.records.findLast(
    (r) => r.type === "config" && r.fingerprint === fingerprint,
  );
  const record = old || {
    ...s,
    type: "config",
    fingerprint,
    operation: newID(),
    digest,
    expected,
    journalRevision: snapshot.revision,
  };
  // Retain all original owner domains conservatively, including unchanged ones.
  // Old tab-format records get authority only after the server checks their receipt.
  const legacyScope = old && !old.accessDomains;
  if (!record.accessDomains)
    record.accessDomains = state.session.scopes
      .filter((v) => v.tenant === s.tenant)
      .map((v) => v.domain);
  await currentAuthority(record);
  const body = {
    operationId: record.operation,
    reason: "POLICY_CHANGE",
    document: base64(file),
    expectedRevision: record.expected,
  };
  // An uncertain previously submitted operation must replay its original
  // preview, even if the effect already advanced the configuration pointer.
  let preview = old?.preview;
  if (preview) {
    try {
      await api(`/api/v1/tenants/${s.tenant}/operations/${record.operation}`);
    } catch (e) {
      if (e.message !== "UNAVAILABLE") throw e;
      // A retained request may never have reached the service. In that case
      // the original revision must still pass a fresh authorized preview.
      preview = null;
    }
  }
  if (!preview)
    preview = await api(`${nodePath(s)}/configuration/preview`, { method: "POST", body });
  if (legacyScope) await journal.authorize(record.operation, record.accessDomains);
  if (key !== scopeKey() || edit !== state.configEdit) return;
  if (
    preview.candidateDigest !== digest ||
    preview.node !== s.node ||
    preview.currentRevision !== record.expected ||
    !Array.isArray(preview.changes)
  )
    throw new Error("CONFLICT");
  body.previewDigest = digest;
  record.preview = preview;
  state.config = { record, body };
  const box = $("config-changes");
  box.replaceChildren();
  pairs(box, [
    ["node", s.node],
    ["digest", digest],
    ["revision", preview.currentRevision],
    ["candidateRevision", preview.candidateRevision],
    ["capacity", preview.capacityState],
    ["bytes", preview.estimatedBytes],
  ]);
  const list = el("div");
  table(
    list,
    ["change", "domain", "before", "after"],
    preview.changes.map((c) => [c.kind, c.domain, c.before.join(", "), c.after.join(", ")]),
  );
  box.append(list);
  $("config-preview").hidden = false;
  $("apply-config").focus();
  notice("configReady");
}
async function readReceipt(record) {
  const epoch = state.epoch;
  if (!ID.test(record.tenant) || !ID.test(record.operation)) throw new Error("INVALID");
  const result = await api(`/api/v1/tenants/${record.tenant}/operations/${record.operation}`);
  if (result.operationId !== record.operation) throw new Error("INVALID");
  let confirmed = result;
  if (state.journal.some((r) => r.operation === record.operation)) {
    try {
      confirmed = await journal.receipt(record.operation, result);
    } catch {
      throw new Error("STORAGE_AFTER");
    }
  }
  if (epoch !== state.epoch) return;
  $("receipt-result").textContent = JSON.stringify(confirmed, null, 2);
  notice("admitted");
}
function resolutionPath(record) {
  if (!ID.test(record.tenant) || !ID.test(record.operation)) throw new Error("INVALID");
  return `/api/v1/tenants/${record.tenant}/operations/${record.operation}/resolution`;
}
async function reviewResolution(record) {
  if (state.busy || !state.session?.roles.includes("owner")) throw new Error("DENIED");
  const epoch = state.epoch;
  await currentAuthority(record);
  if (!state.session.roles.includes("owner")) throw new Error("DENIED");
  const preview = await api(resolutionPath(record));
  if (epoch !== state.epoch) return;
  if (
    preview.format !== "outpost-management-resolution-preview-1" ||
    preview.operationId !== record.operation ||
    preview.node !== record.node ||
    !ID.test(preview.targetRequestDigest) ||
    !Array.isArray(preview.domains) ||
    !preview.domains.every((d) => ID.test(d))
  )
    throw new Error("INVALID");
  const retained = journalSnapshot().records.find((r) => r.operation === record.operation);
  if (!retained) throw new Error("CONFLICT");
  const body = retained.resolution?.body || {
    operationId: newID(),
    targetRequestDigest: preview.targetRequestDigest,
    reason: "ABANDON_UNPUBLISHED",
  };
  const retry = preview.reason === "ALREADY_ABANDONED" && retained.resolution;
  state.resolution = {
    record: retained,
    body,
    preview,
    allowed: preview.canAbandon || Boolean(retry),
  };
  $("resolution-summary").textContent = JSON.stringify(
    { ...preview, resolutionOperationId: body.operationId },
    null,
    2,
  );
  $("resolution-review").hidden = false;
  $("confirm-resolution").disabled = !state.resolution.allowed;
  notice(
    state.resolution.allowed ? "resolutionReady" : "resolutionUnavailable",
    state.resolution.allowed ? "info" : "error",
  );
  (state.resolution.allowed ? $("confirm-resolution") : $("cancel-resolution")).focus();
}
async function submitResolution() {
  const review = state.resolution;
  if (!review?.allowed || state.busy) return;
  state.busy = true;
  $("confirm-resolution").disabled = true;
  try {
    await journal.dispatch(async () => {
      await currentAuthority(review.record);
      if (!state.session.roles.includes("owner")) throw new Error("DENIED");
      const body = await journal.prepareResolution(review.record.operation, review.body);
      $("resolution-summary").textContent = JSON.stringify(
        { ...review.preview, resolutionOperationId: body.operationId },
        null,
        2,
      );
      let result;
      try {
        result = await api(resolutionPath(review.record), { method: "POST", body });
      } catch (e) {
        if (["OFFLINE", "UNAVAILABLE"].includes(e.message)) notice("uncertain", "error");
        else showError(e);
        return;
      }
      if (result.operationId !== body.operationId || result.state !== "COMPLETE")
        throw new Error("INVALID");
      try {
        await journal.resolved(review.record.operation, result);
      } catch {
        throw new Error("STORAGE_AFTER");
      }
      await readReceipt(review.record);
      $("resolution-review").hidden = true;
      state.resolution = null;
      notice("resolutionDone");
    });
  } finally {
    state.busy = false;
    $("confirm-resolution").disabled = !state.resolution?.allowed;
  }
}
function renderOperations() {
  const records = state.journal.filter((r) => r.tenant === $("tenant").value && recordAllowed(r));
  table(
    $("operations"),
    ["operationId", "node", "kind", "status", "details"],
    records.map((r) => [
      r.operation,
      r.node,
      r.type === "command" ? label(r.body?.kind) : tr("configuration"),
      r.receipt ? label(r.receipt.state) : tr("pending"),
      () => {
        const box = el("div", undefined, "actions");
        box.append(button("refreshReceipt", () => readReceipt(r)));
        if (!terminal(r) && state.session?.roles.includes("owner"))
          box.append(button("reviewResolution", () => reviewResolution(r)));
        if (!terminal(r))
          box.append(
            button("retry", () =>
              r.type === "command" ? submit(r) : Promise.reject(new Error("FILE")),
            ),
          );
        else box.append(button("forget", () => journal.remove(r.operation)));
        return box;
      },
    ]),
  );
}
async function loadAudit(more = false) {
  const tenant = $("tenant").value,
    epoch = state.epoch;
  if (!ID.test(tenant)) throw new Error("INVALID");
  try {
    const page = await api(
      `/api/v1/tenants/${tenant}/audit?limit=50${more && state.auditCursor ? `&cursor=${encodeURIComponent(state.auditCursor)}` : ""}`,
    );
    if (epoch !== state.epoch) return;
    if (!Array.isArray(page.items) || page.items.length > 50) throw new Error("INVALID");
    state.audit = page.items;
    state.auditCursor = page.nextCursor || "";
    renderAudit();
  } catch (e) {
    if (epoch !== state.epoch) return;
    if (e.message === "CONFLICT") {
      state.audit = null;
      state.auditCursor = "";
      renderAudit();
    }
    throw e;
  }
}
function renderAudit() {
  $("audit-more").hidden = !state.auditCursor;
  table(
    $("audit"),
    ["sequence", "operationId", "actor", "kind", "reason", "details"],
    (state.audit || []).map((a) => [
      a.sequence,
      a.operationId,
      a.actor,
      a.action,
      a.reason,
      () => {
        const d = el("details");
        d.append(el("summary", tr("details")), el("pre", JSON.stringify(a, null, 2)));
        return d;
      },
    ]),
  );
}
function on(id, event, action) {
  $(id).addEventListener(event, (e) => {
    e.preventDefault();
    Promise.resolve().then(action).catch(showError);
  });
}
on("language", "change", () => {
  lang = $("language").value;
  try {
    localStorage.setItem("outpost-language", lang);
  } catch {
    /* Optional preference. */
  }
  translate();
});
on("tenant", "change", () => loadNodes());
on("node", "change", selectNode);
on("domain", "change", () => {
  resetView();
  return loadDomain();
});
on("refresh", "click", () =>
  !state.session ? loadSession() : $("domain").value ? loadDomain() : loadNodes(),
);
on("nodes-more", "click", () => loadNodes(true));
on("kind", "change", () => {
  invalidateCommand();
  commandFields();
});
for (const id of ["generation", "job", "preset", "versions", "permit"])
  on(id, "input", invalidateCommand);
on("command-form", "submit", reviewCommand);
on("send-command", "click", () => (state.command ? submit(state.command) : null));
on("cancel-review", "click", () => {
  invalidateCommand();
  $("kind").focus();
});
on("new-command", "click", () => {
  const old = state.command && state.journal.find((r) => r.operation === state.command.operation);
  if (old && !terminal(old)) {
    notice("uncertain", "error");
    return;
  }
  if (old) state.newAfter = old.operation;
  invalidateCommand();
  $("command-form").reset();
  commandFields();
  notice("newReady");
});
on("config-file", "change", () => {
  state.configEdit++;
  state.config = null;
  $("config-preview").hidden = true;
});
on("config-form", "submit", previewConfig);
on("apply-config", "click", () =>
  state.config ? submit(state.config.record, state.config.body) : null,
);
on("confirm-resolution", "click", submitResolution);
on("cancel-resolution", "click", () => {
  state.resolution = null;
  $("resolution-review").hidden = true;
});
on("receipt-form", "submit", () =>
  readReceipt({ tenant: $("tenant").value, operation: $("operation-id").value }),
);
on("audit-refresh", "click", () => loadAudit());
on("audit-more", "click", () => loadAudit(true));
translate();
loadSession();
