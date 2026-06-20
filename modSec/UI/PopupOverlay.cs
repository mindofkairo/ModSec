using ModSec.Models;
using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;

namespace ModSec.UI;

public class PopupOverlay
{
    private const int SortingOrder = 32000;
    private const int ToastSortingOrder = SortingOrder + 1;

    private readonly Queue<AdminPopup> _queuedPopups = new();
    private readonly Queue<AdminPopup> _queuedToasts = new();

    private GameObject? _root;
    private GameObject? _toastRoot;
    private Text? _eyebrowText;
    private Text? _titleText;
    private Text? _alertStripText;
    private Text? _messageText;
    private RectTransform? _messageViewport;
    private RectTransform? _messageScrollbarRect;
    private RectTransform? _messageContent;
    private ScrollRect? _messageScroll;
    private Text? _buttonText;
    private Text? _secondaryButtonText;
    private Text? _footerText;
    private Image? _accentBar;
    private Image? _alertStripImage;
    private Image? _infoBoxImage;
    private Image? _buttonImage;
    private Image? _secondaryButtonImage;
    private Button? _button;
    private Button? _secondaryButton;
    private Text? _toastTitleText;
    private Text? _toastMessageText;
    private Image? _toastAccent;
    private AdminPopup? _activePopup;
    private EnforcementResponse? _activeEnforcement;
    private AdminPopup? _activeToast;
    private bool _enforcementRequiresQuit;
    private string _activeEnforcementKey = "";
    private float _toastExpiresAt;

    public void Enqueue(AdminPopup popup)
    {
        if (IsToast(popup))
        {
            _queuedToasts.Enqueue(popup);
            ShowNextToast();
            return;
        }

        _queuedPopups.Enqueue(popup);
        if (_activePopup == null && _activeEnforcement == null)
        {
            ShowNextPopup();
        }
    }

    public void ShowBlocking(string title, string message, bool requiresQuit)
    {
        ShowEnforcement(new EnforcementResponse
        {
            Status = "blocked",
            Message = message,
            Strikes = 0,
            StrikeLimit = 0,
            Violations =
            [
                new Violation
                {
                    Severity = "block",
                    Reason = title
                }
            ]
        }, requiresQuit);
    }

    public void ShowConsent(string message, Action acceptAction, Action declineAction)
    {
        _activePopup = null;
        _activeEnforcement = null;
        SetContent(
            "ModSec Host Rule Disclosure",
            message,
            false,
            "Accept to allow this host's ModSec checks. Decline to keep your data local; raid access may be blocked.",
            "Decline",
            () =>
            {
                Hide();
                acceptAction();
            },
            () =>
            {
                Hide();
                declineAction();
            },
            "Accept");
    }

    public void ShowConsentRequired(Action reviewAction)
    {
        _activePopup = null;
        _activeEnforcement = null;
        SetContent(
            "Raid Access Requires Consent",
            "You declined this host's ModSec disclosure. No ModSec scan results or client environment data will be sent.\n\nThis host may block raid access until consent is accepted.",
            false,
            "You can review the disclosure again if you changed your mind.",
            "Review Disclosure",
            () =>
            {
                Hide();
            },
            () =>
            {
                reviewAction();
            },
            "Close");
    }

    public void ShowConsentRestartRequired()
    {
        _activePopup = null;
        _activeEnforcement = null;
        SetContent(
            "Raid Access Suspended",
            "ModSec consent was revoked or changed after it had already been accepted for this game launch.\n\nTo prevent mid-raid consent toggling from bypassing host rule checks, ModSec will not resume reporting in this game process. Restart the game, review the disclosure, and accept it before entering raid.",
            true,
            "This restriction is local to this host/session. No additional ModSec scan reports will be sent until consent is accepted after restart.",
            null,
            () =>
            {
                Application.Quit();
            },
            null,
            "Exit Game");
    }

    public void ShowEnforcement(EnforcementResponse response, bool requiresQuit, Action? recheckAction = null)
    {
        var responseKey = BuildEnforcementKey(response);
        if (_activeEnforcement != null
            && _root != null
            && _root.activeSelf
            && string.Equals(_activeEnforcementKey, responseKey, StringComparison.Ordinal))
        {
            return;
        }

        _activePopup = null;
        _activeEnforcement = response;
        _activeEnforcementKey = responseKey;
        _enforcementRequiresQuit = requiresQuit;
        RenderActive(recheckAction);
    }

    public void ClearEnforcement()
    {
        _activeEnforcement = null;
        _activeEnforcementKey = "";
        Hide();
        ShowNextPopup();
    }

    public void Draw()
    {
        if (_root != null && (_activeEnforcement != null || _activePopup != null) && !_root.activeSelf)
        {
            _root.SetActive(true);
        }

        if (_activeToast != null && Time.realtimeSinceStartup >= _toastExpiresAt)
        {
            _activeToast = null;
            ShowNextToast();
        }
    }

    private void RenderActive(Action? recheckAction = null)
    {
        EnsureUi();

        if (_activeEnforcement != null)
        {
            RenderEnforcement(_activeEnforcement, _enforcementRequiresQuit, recheckAction);
            return;
        }

        if (_activePopup != null)
        {
            RenderPopup(_activePopup);
            return;
        }

        Hide();
    }

    private void RenderEnforcement(EnforcementResponse response, bool requiresQuit, Action? recheckAction)
    {
        var title = response.Status switch
        {
            "warn" => "ModSec Warning",
            "banned" => "Server Lockout",
            _ => "Raid Access Blocked"
        };
        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(response.Message))
        {
            lines.Add(response.Message);
        }

        if (response.Violations.Count > 0)
        {
            lines.Add("");
            lines.Add(response.Violations.Any(IsConfigViolation) ? "<b>POLICY DETAILS</b>" : "<b>DETECTED ITEMS</b>");
        }

        var shownViolations = 0;
        foreach (var violation in response.Violations.Take(8))
        {
            if (shownViolations > 0)
            {
                lines.Add("");
            }

            lines.AddRange(FormatViolation(violation));
            shownViolations++;
        }

        var footer = response.Status == "banned"
            ? "Local host restriction. Contact the host admin if this was applied in error."
            : "Raid access stays blocked until these issues are fixed and pass recheck.";

        var blockLike = response.Status != "warn";
        var primaryLabel = blockLike && recheckAction != null ? "Recheck Now" : null;
        var secondaryLabel = blockLike && recheckAction != null ? "Acknowledge" : null;
        UnityEngine.Events.UnityAction primaryAction = blockLike && recheckAction != null
            ? () =>
            {
                _activeEnforcement = null;
                _activeEnforcementKey = "";
                Hide();
                recheckAction();
            }
            : () =>
            {
                _activeEnforcement = null;
                _activeEnforcementKey = "";
                Hide();
                ShowNextPopup();
            };
        UnityEngine.Events.UnityAction? secondaryAction = secondaryLabel == null
            ? null
            : () =>
            {
                _activeEnforcement = null;
                _activeEnforcementKey = "";
                Hide();
                ShowNextPopup();
            };
        SetContent(title, string.Join("\n", lines), false, footer, secondaryLabel, primaryAction, secondaryAction, primaryLabel);
    }

    private void RenderPopup(AdminPopup popup)
    {
        SetContent(popup.Title, popup.Message, popup.RequiresQuit, GetPopupFooter(popup), null, () =>
        {
            if (popup.RequiresQuit)
            {
                Application.Quit();
                return;
            }

            _activePopup = null;
            ShowNextPopup();
        }, tone: PopupTone(popup));
    }

    private void SetContent(
        string title,
        string message,
        bool quitButton,
        string footer,
        string? secondaryLabel,
        UnityEngine.Events.UnityAction primaryAction,
        UnityEngine.Events.UnityAction? secondaryAction = null,
        string? primaryLabel = null,
        string tone = "info")
    {
        EnsureUi();
        _root!.SetActive(true);
        var isBlock = quitButton
                      || title.Contains("blocked", StringComparison.OrdinalIgnoreCase)
                      || title.Contains("lockout", StringComparison.OrdinalIgnoreCase)
                      || title.Contains("suspended", StringComparison.OrdinalIgnoreCase);
        _eyebrowText!.gameObject.SetActive(!isBlock);
        _eyebrowText.text = isBlock ? "" : "SERVER NOTICE";
        _titleText!.text = isBlock ? "SECURITY ALERT" : title.ToUpperInvariant();
        _alertStripImage!.gameObject.SetActive(isBlock);
        _alertStripText!.gameObject.SetActive(isBlock);
        _infoBoxImage!.gameObject.SetActive(!string.IsNullOrWhiteSpace(footer));
        _alertStripText.text = GetAlertStripText(title);
        if (_messageViewport != null)
        {
            _messageViewport.offsetMin = new Vector2(64f, isBlock ? 156f : 132f);
            _messageViewport.offsetMax = new Vector2(-74f, isBlock ? -158f : -118f);
        }

        if (_messageScrollbarRect != null)
        {
            _messageScrollbarRect.offsetMin = new Vector2(-58f, isBlock ? 156f : 132f);
            _messageScrollbarRect.offsetMax = new Vector2(-46f, isBlock ? -158f : -118f);
        }

        _messageText!.text = message;
        UpdateMessageScroll();
        _buttonText!.text = primaryLabel ?? (quitButton ? "Exit Game" : "Acknowledge");
        _footerText!.text = footer;
        _accentBar!.color = isBlock ? UiColors.AlertRed : GetSeverityColor(tone);
        _buttonImage!.color = isBlock && !quitButton ? UiColors.ButtonPaper : isBlock ? UiColors.ButtonDanger : UiColors.ButtonNormal;
        _buttonText.color = isBlock && !quitButton ? UiColors.ButtonDarkText : UiColors.PrimaryText;
        _button!.onClick.RemoveAllListeners();
        _button.onClick.AddListener(primaryAction);

        var showSecondary = !string.IsNullOrWhiteSpace(secondaryLabel) && secondaryAction != null;
        _secondaryButton!.gameObject.SetActive(showSecondary);
        if (!showSecondary)
        {
            return;
        }

        _secondaryButtonText!.text = secondaryLabel;
        _secondaryButtonImage!.color = isBlock ? UiColors.ButtonOutline : UiColors.ButtonNormal;
        _secondaryButtonText.color = isBlock ? UiColors.BodyText : UiColors.PrimaryText;
        _secondaryButton.onClick.RemoveAllListeners();
        _secondaryButton.onClick.AddListener(secondaryAction);
    }

    private static string GetAlertStripText(string title)
    {
        if (title.Contains("consent", StringComparison.OrdinalIgnoreCase)
            || title.Contains("suspended", StringComparison.OrdinalIgnoreCase))
        {
            return "Host rule disclosure required";
        }

        return title.Contains("lockout", StringComparison.OrdinalIgnoreCase)
            ? "Raid access locked until the host restriction expires"
            : "Raid access blocked until listed issues are fixed";
    }

    private static string BuildEnforcementKey(EnforcementResponse response)
    {
        var violations = response.Violations
            .Select(violation => string.Join("|",
                violation.Category,
                violation.RuleId,
                violation.Path,
                violation.Setting,
                violation.ActualValue,
                violation.ExpectedValue))
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        return string.Join("::", response.Status, string.Join(";;", violations));
    }

    private void UpdateMessageScroll()
    {
        if (_messageText == null || _messageContent == null || _messageScroll == null)
        {
            return;
        }

        Canvas.ForceUpdateCanvases();
        var viewportHeight = ((RectTransform)_messageScroll.viewport).rect.height;
        var preferredHeight = Mathf.Max(viewportHeight, _messageText.preferredHeight + 18f);
        _messageContent.sizeDelta = new Vector2(0f, preferredHeight);
        _messageText.rectTransform.sizeDelta = new Vector2(-18f, preferredHeight);
        _messageScroll.verticalNormalizedPosition = 1f;
    }

    private void ShowNextToast()
    {
        EnsureToastUi();
        if (_activeToast != null)
        {
            return;
        }

        if (_queuedToasts.Count == 0)
        {
            _toastRoot?.SetActive(false);
            return;
        }

        _activeToast = _queuedToasts.Dequeue();
        _toastTitleText!.text = _activeToast.Title;
        _toastMessageText!.text = _activeToast.Message;
        _toastAccent!.color = GetSeverityColor(_activeToast.Severity);
        _toastExpiresAt = Time.realtimeSinceStartup + Mathf.Clamp(_activeToast.DurationSeconds, 2, 60);
        ApplyToastPosition(_activeToast.Position);
        _toastRoot!.SetActive(true);
    }

    private void ShowNextPopup()
    {
        if (_queuedPopups.Count > 0)
        {
            _activePopup = _queuedPopups.Dequeue();
            RenderActive();
            return;
        }

        Hide();
    }

    private void Hide()
    {
        if (_root != null)
        {
            _root.SetActive(false);
        }
    }

    private static bool IsToast(AdminPopup popup)
    {
        return popup.Kind.Equals("toast", StringComparison.OrdinalIgnoreCase);
    }

    private static string PopupTone(AdminPopup popup)
    {
        if (popup.Kind.Equals("kick", StringComparison.OrdinalIgnoreCase)
            || popup.Kind.Equals("ban", StringComparison.OrdinalIgnoreCase)
            || popup.RequiresQuit)
        {
            return "block";
        }

        return string.IsNullOrWhiteSpace(popup.Severity) ? popup.Kind : popup.Severity;
    }

    private static string GetPopupFooter(AdminPopup popup)
    {
        if (popup.RequiresQuit)
        {
            return "Raid access restricted by this host.";
        }

        return popup.Kind.Equals("warning", StringComparison.OrdinalIgnoreCase)
            ? "Acknowledge this warning to continue."
            : "Acknowledge to continue.";
    }

    private static Color GetSeverityColor(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "block" => UiColors.AlertRed,
            "warning" => UiColors.WarningAmber,
            "warn" => UiColors.WarningAmber,
            "kick" => UiColors.AlertRed,
            "ban" => UiColors.AlertRed,
            "information" => UiColors.TarkovTan,
            "info" => UiColors.TarkovTan,
            "toast" => UiColors.TarkovTan,
            "dialog" => UiColors.TarkovTan,
            _ => UiColors.SoftOlive
        };
    }

    private static IEnumerable<string> FormatViolation(Violation violation)
    {
        if (IsConfigViolation(violation))
        {
            var setting = string.IsNullOrWhiteSpace(violation.Setting) ? violation.RuleId : violation.Setting;
            var actual = string.IsNullOrWhiteSpace(violation.ActualValue) ? "unknown" : violation.ActualValue;
            var expected = string.IsNullOrWhiteSpace(violation.ExpectedValue) ? "the server allowed value" : violation.ExpectedValue;

            yield return DetailRow("Detected Item", $"<color=#d84a45>{setting}</color>");
            yield return DetailRow("Rule Triggered", "Host restricted config value");
            yield return DetailRow("Current", $"<color=#d84a45>{actual}</color>");
            yield return DetailRow("Allowed", expected);
            if (!string.IsNullOrWhiteSpace(violation.Path))
            {
                yield return DetailRow("File", violation.Path);
            }

            yield break;
        }

        yield return DetailRow("Detected Item", $"<color=#d84a45>{violation.Reason}</color>");
        yield return DetailRow("Rule Triggered", violation.RuleId);
        if (!string.IsNullOrWhiteSpace(violation.Path))
        {
            yield return DetailRow("File", violation.Path);
        }
    }

    private static string DetailRow(string label, string value)
    {
        return $"<b>{label.PadRight(14)}:</b> {value}";
    }

    private static bool IsConfigViolation(Violation violation)
    {
        return violation.Category.Equals("config", StringComparison.OrdinalIgnoreCase)
               || violation.Path.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase)
               || violation.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
    }


    private void EnsureUi()
    {
        if (_root != null)
        {
            return;
        }

        EnsureEventSystem();

        _root = new GameObject("ModSec_BlockingOverlay");
        UnityEngine.Object.DontDestroyOnLoad(_root);

        var canvas = _root.AddComponent<Canvas>();
        canvas.renderMode = RenderMode.ScreenSpaceOverlay;
        canvas.sortingOrder = SortingOrder;
        _root.AddComponent<GraphicRaycaster>();

        var scaler = _root.AddComponent<CanvasScaler>();
        scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
        scaler.referenceResolution = new Vector2(1920f, 1080f);
        scaler.matchWidthOrHeight = 0.5f;

        var blocker = CreateRect("Blocker", _root.transform);
        Stretch(blocker);
        var blockerImage = blocker.gameObject.AddComponent<Image>();
        blockerImage.color = UiColors.Backdrop;
        blockerImage.raycastTarget = true;

        var panel = CreateRect("Dialog", blocker.transform);
        panel.sizeDelta = new Vector2(900f, 640f);
        panel.anchorMin = new Vector2(0.5f, 0.5f);
        panel.anchorMax = new Vector2(0.5f, 0.5f);
        panel.pivot = new Vector2(0.5f, 0.5f);
        panel.anchoredPosition = Vector2.zero;
        var panelImage = panel.gameObject.AddComponent<Image>();
        panelImage.color = UiColors.Panel;
        panelImage.raycastTarget = true;

        CreateBorder(panel, UiColors.BorderDark, 2f);
        CreateInset(panel, 12f, UiColors.BorderSoft);

        var header = CreateRect("HeaderBand", panel);
        header.anchorMin = new Vector2(0f, 1f);
        header.anchorMax = new Vector2(1f, 1f);
        header.pivot = new Vector2(0.5f, 1f);
        header.anchoredPosition = Vector2.zero;
        header.sizeDelta = new Vector2(0f, 106f);
        var headerImage = header.gameObject.AddComponent<Image>();
        headerImage.color = UiColors.Header;
        headerImage.raycastTarget = false;

        _accentBar = CreateImage("AccentBar", panel, UiColors.WarningAmber);
        _accentBar.rectTransform.anchorMin = new Vector2(0f, 1f);
        _accentBar.rectTransform.anchorMax = new Vector2(1f, 1f);
        _accentBar.rectTransform.pivot = new Vector2(0.5f, 1f);
        _accentBar.rectTransform.anchoredPosition = Vector2.zero;
        _accentBar.rectTransform.sizeDelta = new Vector2(0f, 5f);

        _eyebrowText = CreateText("Eyebrow", panel, 12, FontStyle.Bold, TextAnchor.UpperCenter, UiColors.MutedText);
        _eyebrowText.rectTransform.anchorMin = new Vector2(0f, 1f);
        _eyebrowText.rectTransform.anchorMax = new Vector2(1f, 1f);
        _eyebrowText.rectTransform.pivot = new Vector2(0.5f, 1f);
        _eyebrowText.rectTransform.anchoredPosition = new Vector2(0f, -22f);
        _eyebrowText.rectTransform.sizeDelta = new Vector2(-72f, 20f);

        _titleText = CreateText("Title", panel, 28, FontStyle.Bold, TextAnchor.MiddleCenter, UiColors.PrimaryText);
        _titleText.rectTransform.anchorMin = new Vector2(0f, 1f);
        _titleText.rectTransform.anchorMax = new Vector2(1f, 1f);
        _titleText.rectTransform.pivot = new Vector2(0.5f, 1f);
        _titleText.rectTransform.anchoredPosition = new Vector2(0f, -34f);
        _titleText.rectTransform.sizeDelta = new Vector2(-72f, 54f);
        var titleShadow = _titleText.gameObject.AddComponent<Shadow>();
        titleShadow.effectColor = new Color(0f, 0f, 0f, 0.8f);
        titleShadow.effectDistance = new Vector2(1f, -1f);

        var divider = CreateImage("Divider", panel, UiColors.BorderSoft);
        divider.rectTransform.anchorMin = new Vector2(0f, 1f);
        divider.rectTransform.anchorMax = new Vector2(1f, 1f);
        divider.rectTransform.pivot = new Vector2(0.5f, 1f);
        divider.rectTransform.anchoredPosition = new Vector2(0f, -106f);
        divider.rectTransform.sizeDelta = new Vector2(-34f, 1f);

        _alertStripImage = CreateImage("AlertStrip", panel, UiColors.AlertStrip);
        _alertStripImage.rectTransform.anchorMin = new Vector2(0f, 1f);
        _alertStripImage.rectTransform.anchorMax = new Vector2(1f, 1f);
        _alertStripImage.rectTransform.pivot = new Vector2(0.5f, 1f);
        _alertStripImage.rectTransform.anchoredPosition = new Vector2(0f, -124f);
        _alertStripImage.rectTransform.sizeDelta = new Vector2(-38f, 36f);
        CreateBorder(_alertStripImage.rectTransform, UiColors.AlertBorder, 1f);

        _alertStripText = CreateText("AlertStripText", _alertStripImage.rectTransform, 16, FontStyle.Normal, TextAnchor.MiddleCenter, UiColors.AlertText);
        Stretch(_alertStripText.rectTransform);

        var viewport = CreateRect("MessageViewport", panel);
        _messageViewport = viewport;
        viewport.anchorMin = new Vector2(0f, 0f);
        viewport.anchorMax = new Vector2(1f, 1f);
        viewport.offsetMin = new Vector2(64f, 156f);
        viewport.offsetMax = new Vector2(-74f, -158f);
        var viewportImage = viewport.gameObject.AddComponent<Image>();
        viewportImage.color = new Color(1f, 1f, 1f, 0.01f);
        viewportImage.raycastTarget = true;
        viewport.gameObject.AddComponent<RectMask2D>();

        _messageContent = CreateRect("MessageContent", viewport);
        _messageContent.anchorMin = new Vector2(0f, 1f);
        _messageContent.anchorMax = new Vector2(1f, 1f);
        _messageContent.pivot = new Vector2(0.5f, 1f);
        _messageContent.anchoredPosition = Vector2.zero;
        _messageContent.sizeDelta = new Vector2(0f, 1f);

        _messageText = CreateText("Message", _messageContent, 18, FontStyle.Normal, TextAnchor.UpperLeft, UiColors.BodyText);
        _messageText.rectTransform.anchorMin = new Vector2(0f, 1f);
        _messageText.rectTransform.anchorMax = new Vector2(1f, 1f);
        _messageText.rectTransform.pivot = new Vector2(0.5f, 1f);
        _messageText.rectTransform.anchoredPosition = Vector2.zero;
        _messageText.rectTransform.sizeDelta = new Vector2(-18f, 320f);
        _messageText.lineSpacing = 1.2f;
        _messageText.supportRichText = true;
        _messageText.font = Font.CreateDynamicFontFromOSFont("Consolas", 18);

        _messageScroll = viewport.gameObject.AddComponent<ScrollRect>();
        _messageScroll.content = _messageContent;
        _messageScroll.viewport = viewport;
        _messageScroll.horizontal = false;
        _messageScroll.vertical = true;
        _messageScroll.movementType = ScrollRect.MovementType.Clamped;
        _messageScroll.scrollSensitivity = 34f;

        var scrollbarRect = CreateRect("MessageScrollbar", panel);
        _messageScrollbarRect = scrollbarRect;
        scrollbarRect.anchorMin = new Vector2(1f, 0f);
        scrollbarRect.anchorMax = new Vector2(1f, 1f);
        scrollbarRect.pivot = new Vector2(1f, 0.5f);
        scrollbarRect.offsetMin = new Vector2(-58f, 156f);
        scrollbarRect.offsetMax = new Vector2(-46f, -158f);
        var scrollbarTrack = scrollbarRect.gameObject.AddComponent<Image>();
        scrollbarTrack.color = new Color(0.08f, 0.09f, 0.075f, 0.76f);
        scrollbarTrack.raycastTarget = true;

        var handleRect = CreateRect("Handle", scrollbarRect);
        Stretch(handleRect);
        var handleImage = handleRect.gameObject.AddComponent<Image>();
        handleImage.color = UiColors.ScrollHandle;
        handleImage.raycastTarget = true;

        var scrollbar = scrollbarRect.gameObject.AddComponent<Scrollbar>();
        scrollbar.direction = Scrollbar.Direction.BottomToTop;
        scrollbar.targetGraphic = handleImage;
        scrollbar.handleRect = handleRect;
        _messageScroll.verticalScrollbar = scrollbar;
        _messageScroll.verticalScrollbarVisibility = ScrollRect.ScrollbarVisibility.AutoHideAndExpandViewport;
        _messageScroll.verticalScrollbarSpacing = 4f;

        _infoBoxImage = CreateImage("FooterInfoBox", panel, UiColors.InfoBox);
        _infoBoxImage.rectTransform.anchorMin = new Vector2(0f, 0f);
        _infoBoxImage.rectTransform.anchorMax = new Vector2(1f, 0f);
        _infoBoxImage.rectTransform.pivot = new Vector2(0.5f, 0f);
        _infoBoxImage.rectTransform.anchoredPosition = new Vector2(0f, 92f);
        _infoBoxImage.rectTransform.sizeDelta = new Vector2(-92f, 42f);
        CreateBorder(_infoBoxImage.rectTransform, UiColors.InfoBorder, 1f);

        _footerText = CreateText("Footer", panel, 12, FontStyle.Normal, TextAnchor.LowerLeft, UiColors.MutedText);
        _footerText.rectTransform.anchorMin = new Vector2(0f, 0f);
        _footerText.rectTransform.anchorMax = new Vector2(1f, 0f);
        _footerText.rectTransform.pivot = new Vector2(0.5f, 0f);
        _footerText.rectTransform.anchoredPosition = new Vector2(0f, 101f);
        _footerText.rectTransform.sizeDelta = new Vector2(-132f, 24f);

        var buttonRect = CreateRect("ActionButton", panel);
        buttonRect.sizeDelta = new Vector2(224f, 48f);
        buttonRect.anchorMin = new Vector2(1f, 0f);
        buttonRect.anchorMax = new Vector2(1f, 0f);
        buttonRect.pivot = new Vector2(1f, 0f);
        buttonRect.anchoredPosition = new Vector2(-46f, 28f);
        _buttonImage = buttonRect.gameObject.AddComponent<Image>();
        _buttonImage.color = UiColors.ButtonDanger;
        _buttonImage.raycastTarget = true;
        _button = buttonRect.gameObject.AddComponent<Button>();
        _button.colors = new ColorBlock
        {
            normalColor = Color.white,
            highlightedColor = UiColors.ButtonHover,
            pressedColor = UiColors.ButtonPressed,
            selectedColor = Color.white,
            disabledColor = new Color(0.25f, 0.25f, 0.25f, 0.8f),
            colorMultiplier = 1f,
            fadeDuration = 0.08f
        };
        CreateBorder(buttonRect, UiColors.ButtonBorder, 1f);

        _buttonText = CreateText("ButtonText", buttonRect, 16, FontStyle.Bold, TextAnchor.MiddleCenter, UiColors.PrimaryText);
        Stretch(_buttonText.rectTransform);

        var secondaryButtonRect = CreateRect("SecondaryActionButton", panel);
        secondaryButtonRect.sizeDelta = new Vector2(188f, 48f);
        secondaryButtonRect.anchorMin = new Vector2(1f, 0f);
        secondaryButtonRect.anchorMax = new Vector2(1f, 0f);
        secondaryButtonRect.pivot = new Vector2(1f, 0f);
        secondaryButtonRect.anchoredPosition = new Vector2(-286f, 28f);
        _secondaryButtonImage = secondaryButtonRect.gameObject.AddComponent<Image>();
        _secondaryButtonImage.color = UiColors.ButtonNormal;
        _secondaryButtonImage.raycastTarget = true;
        _secondaryButton = secondaryButtonRect.gameObject.AddComponent<Button>();
        _secondaryButton.colors = _button.colors;
        CreateBorder(secondaryButtonRect, UiColors.ButtonBorder, 1f);

        _secondaryButtonText = CreateText("SecondaryButtonText", secondaryButtonRect, 16, FontStyle.Bold, TextAnchor.MiddleCenter, UiColors.PrimaryText);
        Stretch(_secondaryButtonText.rectTransform);
        _secondaryButton.gameObject.SetActive(false);

        _root.SetActive(false);
    }

    private void EnsureToastUi()
    {
        if (_toastRoot != null)
        {
            return;
        }

        EnsureEventSystem();
        _toastRoot = new GameObject("ModSec_ToastOverlay");
        UnityEngine.Object.DontDestroyOnLoad(_toastRoot);

        var canvas = _toastRoot.AddComponent<Canvas>();
        canvas.renderMode = RenderMode.ScreenSpaceOverlay;
        canvas.sortingOrder = ToastSortingOrder;

        var scaler = _toastRoot.AddComponent<CanvasScaler>();
        scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
        scaler.referenceResolution = new Vector2(1920f, 1080f);
        scaler.matchWidthOrHeight = 0.5f;

        var panel = CreateRect("Toast", _toastRoot.transform);
        panel.sizeDelta = new Vector2(430f, 118f);
        panel.anchorMin = new Vector2(1f, 1f);
        panel.anchorMax = new Vector2(1f, 1f);
        panel.pivot = new Vector2(1f, 1f);
        panel.anchoredPosition = new Vector2(-28f, -28f);
        var panelImage = panel.gameObject.AddComponent<Image>();
        panelImage.color = UiColors.Panel;
        panelImage.raycastTarget = false;
        CreateBorder(panel, UiColors.BorderSoft, 1f);

        _toastAccent = CreateImage("ToastAccent", panel, UiColors.SoftOlive);
        _toastAccent.rectTransform.anchorMin = new Vector2(0f, 0f);
        _toastAccent.rectTransform.anchorMax = new Vector2(0f, 1f);
        _toastAccent.rectTransform.sizeDelta = new Vector2(5f, 0f);

        _toastTitleText = CreateText("ToastTitle", panel, 15, FontStyle.Bold, TextAnchor.UpperLeft, UiColors.PrimaryText);
        _toastTitleText.rectTransform.anchorMin = new Vector2(0f, 1f);
        _toastTitleText.rectTransform.anchorMax = new Vector2(1f, 1f);
        _toastTitleText.rectTransform.pivot = new Vector2(0.5f, 1f);
        _toastTitleText.rectTransform.anchoredPosition = new Vector2(0f, -16f);
        _toastTitleText.rectTransform.sizeDelta = new Vector2(-42f, 24f);

        _toastMessageText = CreateText("ToastMessage", panel, 13, FontStyle.Normal, TextAnchor.UpperLeft, UiColors.BodyText);
        _toastMessageText.rectTransform.anchorMin = Vector2.zero;
        _toastMessageText.rectTransform.anchorMax = Vector2.one;
        _toastMessageText.rectTransform.offsetMin = new Vector2(24f, 16f);
        _toastMessageText.rectTransform.offsetMax = new Vector2(-18f, -44f);

        _toastRoot.SetActive(false);
    }

    private void ApplyToastPosition(string position)
    {
        if (_toastRoot == null || _toastRoot.transform.childCount == 0)
        {
            return;
        }

        var rect = _toastRoot.transform.GetChild(0) as RectTransform;
        if (rect == null)
        {
            return;
        }

        switch (position.ToLowerInvariant())
        {
            case "topleft":
                rect.anchorMin = new Vector2(0f, 1f);
                rect.anchorMax = new Vector2(0f, 1f);
                rect.pivot = new Vector2(0f, 1f);
                rect.anchoredPosition = new Vector2(28f, -28f);
                break;
            case "bottomleft":
                rect.anchorMin = Vector2.zero;
                rect.anchorMax = Vector2.zero;
                rect.pivot = Vector2.zero;
                rect.anchoredPosition = new Vector2(28f, 28f);
                break;
            case "bottomright":
                rect.anchorMin = new Vector2(1f, 0f);
                rect.anchorMax = new Vector2(1f, 0f);
                rect.pivot = new Vector2(1f, 0f);
                rect.anchoredPosition = new Vector2(-28f, 28f);
                break;
            default:
                rect.anchorMin = Vector2.one;
                rect.anchorMax = Vector2.one;
                rect.pivot = Vector2.one;
                rect.anchoredPosition = new Vector2(-28f, -28f);
                break;
        }
    }

    private static void EnsureEventSystem()
    {
        if (EventSystem.current != null)
        {
            return;
        }

        var eventSystem = new GameObject("ModSec_EventSystem");
        UnityEngine.Object.DontDestroyOnLoad(eventSystem);
        eventSystem.AddComponent<EventSystem>();
        eventSystem.AddComponent<StandaloneInputModule>();
    }

    private static RectTransform CreateRect(string name, Transform parent)
    {
        var gameObject = new GameObject(name);
        gameObject.transform.SetParent(parent, false);
        return gameObject.AddComponent<RectTransform>();
    }

    private static Text CreateText(string name, RectTransform parent, int fontSize, FontStyle fontStyle, TextAnchor alignment, Color color)
    {
        var rect = CreateRect(name, parent);
        var text = rect.gameObject.AddComponent<Text>();
        text.font = Resources.GetBuiltinResource<Font>("Arial.ttf");
        text.fontSize = fontSize;
        text.fontStyle = fontStyle;
        text.alignment = alignment;
        text.color = color;
        text.supportRichText = true;
        text.raycastTarget = false;
        return text;
    }

    private static Image CreateImage(string name, RectTransform parent, Color color)
    {
        var rect = CreateRect(name, parent);
        var image = rect.gameObject.AddComponent<Image>();
        image.color = color;
        image.raycastTarget = false;
        return image;
    }

    private static void CreateInset(RectTransform parent, float inset, Color color)
    {
        const float thickness = 1f;
        var top = CreateImage("InsetTop", parent, color).rectTransform;
        top.anchorMin = new Vector2(0f, 1f);
        top.anchorMax = new Vector2(1f, 1f);
        top.offsetMin = new Vector2(inset, -inset - thickness);
        top.offsetMax = new Vector2(-inset, -inset);

        var bottom = CreateImage("InsetBottom", parent, color).rectTransform;
        bottom.anchorMin = Vector2.zero;
        bottom.anchorMax = new Vector2(1f, 0f);
        bottom.offsetMin = new Vector2(inset, inset);
        bottom.offsetMax = new Vector2(-inset, inset + thickness);

        var left = CreateImage("InsetLeft", parent, color).rectTransform;
        left.anchorMin = Vector2.zero;
        left.anchorMax = new Vector2(0f, 1f);
        left.offsetMin = new Vector2(inset, inset);
        left.offsetMax = new Vector2(inset + thickness, -inset);

        var right = CreateImage("InsetRight", parent, color).rectTransform;
        right.anchorMin = new Vector2(1f, 0f);
        right.anchorMax = Vector2.one;
        right.offsetMin = new Vector2(-inset - thickness, inset);
        right.offsetMax = new Vector2(-inset, -inset);
    }

    private static void CreateBorder(RectTransform parent, Color color, float thickness)
    {
        AddEdge("Top", parent, color, new Vector2(0f, 1f), new Vector2(1f, 1f), new Vector2(0f, 1f), new Vector2(0f, 0f), new Vector2(0f, thickness));
        AddEdge("Bottom", parent, color, Vector2.zero, new Vector2(1f, 0f), new Vector2(0f, 0f), new Vector2(0f, 0f), new Vector2(0f, thickness));
        AddEdge("Left", parent, color, Vector2.zero, new Vector2(0f, 1f), new Vector2(0f, 0f), new Vector2(0f, 0f), new Vector2(thickness, 0f));
        AddEdge("Right", parent, color, new Vector2(1f, 0f), Vector2.one, new Vector2(1f, 0f), new Vector2(0f, 0f), new Vector2(thickness, 0f));
    }

    private static void AddEdge(string name, RectTransform parent, Color color, Vector2 anchorMin, Vector2 anchorMax, Vector2 pivot, Vector2 position, Vector2 size)
    {
        var edge = CreateImage($"Border{name}", parent, color).rectTransform;
        edge.anchorMin = anchorMin;
        edge.anchorMax = anchorMax;
        edge.pivot = pivot;
        edge.anchoredPosition = position;
        edge.sizeDelta = size;
    }

    private static void Stretch(RectTransform rect)
    {
        rect.anchorMin = Vector2.zero;
        rect.anchorMax = Vector2.one;
        rect.offsetMin = Vector2.zero;
        rect.offsetMax = Vector2.zero;
    }

    private static class UiColors
    {
        public static readonly Color Backdrop = new(0.01f, 0.012f, 0.012f, 0.88f);
        public static readonly Color Panel = new(0.055f, 0.065f, 0.058f, 0.985f);
        public static readonly Color Header = new(0.088f, 0.101f, 0.091f, 0.98f);
        public static readonly Color BorderDark = new(0.012f, 0.014f, 0.012f, 1f);
        public static readonly Color BorderSoft = new(0.28f, 0.31f, 0.25f, 0.78f);
        public static readonly Color AlertRed = new(0.86f, 0.16f, 0.14f, 1f);
        public static readonly Color AlertIconCutout = new(0.055f, 0.035f, 0.03f, 1f);
        public static readonly Color AlertText = new(0.96f, 0.22f, 0.2f, 1f);
        public static readonly Color AlertStrip = new(0.14f, 0.055f, 0.052f, 0.94f);
        public static readonly Color AlertBorder = new(0.36f, 0.12f, 0.11f, 0.95f);
        public static readonly Color InfoBox = new(0.07f, 0.075f, 0.065f, 0.88f);
        public static readonly Color InfoBorder = new(0.22f, 0.23f, 0.19f, 0.82f);
        public static readonly Color ScrollHandle = new(0.52f, 0.47f, 0.36f, 1f);
        public static readonly Color WarningAmber = new(0.74f, 0.48f, 0.18f, 1f);
        public static readonly Color TarkovTan = new(0.68f, 0.61f, 0.44f, 1f);
        public static readonly Color SoftOlive = new(0.39f, 0.48f, 0.35f, 1f);
        public static readonly Color PrimaryText = new(0.88f, 0.86f, 0.77f, 1f);
        public static readonly Color BodyText = new(0.73f, 0.72f, 0.64f, 1f);
        public static readonly Color MutedText = new(0.52f, 0.55f, 0.47f, 1f);
        public static readonly Color ButtonDanger = new(0.43f, 0.22f, 0.14f, 1f);
        public static readonly Color ButtonNormal = new(0.22f, 0.30f, 0.22f, 1f);
        public static readonly Color ButtonOutline = new(0.11f, 0.12f, 0.10f, 1f);
        public static readonly Color ButtonPaper = new(0.78f, 0.75f, 0.64f, 1f);
        public static readonly Color ButtonDarkText = new(0.06f, 0.065f, 0.058f, 1f);
        public static readonly Color ButtonHover = new(0.66f, 0.58f, 0.39f, 1f);
        public static readonly Color ButtonPressed = new(0.48f, 0.44f, 0.31f, 1f);
        public static readonly Color ButtonBorder = new(0.62f, 0.53f, 0.35f, 0.9f);
    }
}
