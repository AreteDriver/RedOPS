"""Tests for dashboard mobile responsiveness."""

from redops.web.app import get_dashboard_html


def test_dashboard_html_is_string():
    html = get_dashboard_html()
    assert isinstance(html, str)
    assert len(html) > 0


def test_no_fixed_width_modal():
    """Login modal must not use w-96 which overflows on phones."""
    html = get_dashboard_html()
    assert 'w-96' not in html
    assert 'max-w-sm' in html


def test_modal_uses_responsive_width():
    html = get_dashboard_html()
    assert 'w-full max-w-sm' in html


def test_modal_responsive_padding():
    html = get_dashboard_html()
    assert 'p-6 sm:p-8' in html


def test_scan_target_input_no_fixed_min_width():
    html = get_dashboard_html()
    assert 'min-w-64' not in html
    assert 'sm:min-w-0' in html


def test_scan_target_input_full_width_mobile():
    html = get_dashboard_html()
    assert 'w-full sm:flex-1' in html


def test_scan_preset_full_width_mobile():
    html = get_dashboard_html()
    assert 'w-full sm:w-auto' in html


def test_start_scan_button_full_width_mobile():
    html = get_dashboard_html()
    assert 'h-11 w-full sm:w-auto' in html


def test_login_submit_has_touch_target():
    html = get_dashboard_html()
    assert 'h-11' in html


def test_login_inputs_have_touch_target():
    html = get_dashboard_html()
    # Both username and password inputs should have h-11
    assert html.count('h-11') >= 2


def test_logout_button_has_touch_target():
    html = get_dashboard_html()
    assert 'inline-flex items-center' in html


def test_refresh_button_has_touch_target():
    html = get_dashboard_html()
    assert 'h-11 px-3 inline-flex items-center' in html


def test_view_button_has_touch_target():
    html = get_dashboard_html()
    assert 'h-11 px-3 inline-flex items-center' in html


def test_desktop_table_hidden_on_mobile():
    html = get_dashboard_html()
    assert 'hidden md:block' in html


def test_mobile_cards_present():
    html = get_dashboard_html()
    assert 'md:hidden' in html
    assert 'Mobile cards' in html or 'bg-gray-700/50 rounded-lg p-4' in html


def test_mobile_card_view_button():
    html = get_dashboard_html()
    assert 'View Results' in html


def test_viewport_meta_present():
    html = get_dashboard_html()
    assert 'width=device-width, initial-scale=1.0' in html


def test_chart_js_included():
    html = get_dashboard_html()
    assert 'chart.js@4.4.1' in html


def test_alpine_js_included():
    html = get_dashboard_html()
    assert 'alpinejs' in html


def test_tailwind_cdn_included():
    html = get_dashboard_html()
    assert 'tailwindcss.com' in html


def test_aria_roles_present():
    html = get_dashboard_html()
    assert 'role="banner"' in html
    assert 'role="region"' in html
    assert 'role="dialog"' in html


def test_skip_link_present():
    html = get_dashboard_html()
    assert 'Skip to main content' in html
    assert 'sr-only' in html


def test_login_modal_escape_handler():
    html = get_dashboard_html()
    assert '@keydown.escape.window="showLogin = false"' in html


def test_module_chart_canvas_present():
    html = get_dashboard_html()
    assert 'id="moduleChart"' in html


def test_risk_gauge_canvas_present():
    html = get_dashboard_html()
    assert 'id="riskGauge"' in html


def test_timeline_chart_canvas_present():
    html = get_dashboard_html()
    assert 'id="timelineChart"' in html


def test_all_chart_render_methods_present():
    html = get_dashboard_html()
    assert 'renderModuleChart()' in html
    assert 'renderRiskGauge()' in html
    assert 'renderTimelineChart()' in html


def test_view_results_calls_all_charts():
    html = get_dashboard_html()
    assert 'this.renderSeverityChart();' in html
    assert 'this.renderModuleChart();' in html
    assert 'this.renderRiskGauge();' in html
    assert 'this.renderTimelineChart();' in html
