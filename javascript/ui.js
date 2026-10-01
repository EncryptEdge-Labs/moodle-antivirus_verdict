// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// @package   antivirus_verdict
// @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
// @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later

(function() {
    'use strict';

    if (window.antivirusVerdictUiLoaded) {
        return;
    }
    window.antivirusVerdictUiLoaded = true;

    var THEME_KEY = 'antivirus_verdict_theme';
    var COPY_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">' +
        '<rect x="9" y="9" width="12" height="12" rx="1.5"/>' +
        '<path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>' +
        '</svg>';
    var CHECK_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">' +
        '<path d="M5 12l4 4L19 6"/>' +
        '</svg>';

    function storedTheme() {
        try {
            var stored = window.localStorage.getItem(THEME_KEY);
            if (stored === 'light' || stored === 'dark') {
                return stored;
            }
        } catch (e) {
            return 'dark';
        }
        return 'dark';
    }

    function applyTheme(theme) {
        var root = document.querySelector('.antivirus-verdict');
        if (root) {
            root.setAttribute('data-theme', theme);
        }
        document.documentElement.setAttribute('data-antivirus-verdict-theme', theme);
        if (document.body) {
            document.body.setAttribute('data-antivirus-verdict-theme', theme);
        }
        var toggle = document.querySelector('[data-antivirus-verdict="theme-toggle"]');
        if (toggle) {
            var isLight = theme === 'light';
            toggle.setAttribute('aria-pressed', isLight ? 'true' : 'false');
            toggle.setAttribute('aria-label', isLight ? (toggle.getAttribute('data-label-dark') || '') : (toggle.getAttribute('data-label-light') || ''));
            toggle.setAttribute('title', isLight ? (toggle.getAttribute('data-label-dark') || '') : (toggle.getAttribute('data-label-light') || ''));
            toggle.classList.toggle('is-light', isLight);
        }
    }

    function persistTheme(theme) {
        try {
            window.localStorage.setItem(THEME_KEY, theme);
        } catch (e) {
            // Preference stays for this page only if storage is unavailable.
        }
        applyTheme(theme);
    }

    function filepickerClientId(button) {
        if (!button || !button.id) {
            return '';
        }
        return button.id.indexOf('filepicker-button-') === 0
            ? button.id.slice('filepicker-button-'.length)
            : '';
    }

    function openMoodleFilepicker(form) {
        var button = form.querySelector('.fp-btn-choose, [id^="filepicker-button-"]');
        var clientId = filepickerClientId(button);
        if (clientId && window.M && M.core_filepicker && M.core_filepicker.instances &&
                M.core_filepicker.instances[clientId] &&
                typeof M.core_filepicker.instances[clientId].show === 'function') {
            M.core_filepicker.instances[clientId].show();
            return;
        }
        if (button) {
            button.click();
        }
    }

    function polishScanDropzone() {
        var form = document.querySelector('.antivirus-verdict-scanform');
        if (!form) {
            return;
        }
        var hint = form.querySelector('.antivirus-verdict-dropzone');
        var host = form.querySelector('[id^="file_info_"]') ||
            form.querySelector('.filepicker-filelist') ||
            form.querySelector('.filepicker');
        var real = form.querySelector('.fp-btn-choose, [id^="filepicker-button-"]');
        var fake = form.querySelector('button.antivirus-verdict-dz-choose');
        if (hint && host && hint.parentNode !== host) {
            var leftover = hint.closest('.fitem');
            host.insertBefore(hint, host.firstChild);
            if (leftover && leftover !== host.closest('.fitem')) {
                leftover.setAttribute('hidden', 'hidden');
            }
        }
        if (real && fake && fake !== real && fake.parentNode) {
            var label = (fake.textContent || '').trim();
            real.classList.add('antivirus-verdict-dz-choose');
            real.removeAttribute('hidden');
            real.setAttribute('tabindex', '-1');
            if (label && real.tagName === 'INPUT') {
                real.value = label;
            }
            fake.parentNode.replaceChild(real, fake);
        }
        if (hint) {
            hint.setAttribute('role', 'button');
            hint.setAttribute('tabindex', '0');
            if (!hint.getAttribute('aria-label')) {
                hint.setAttribute('aria-label', (hint.textContent || '').replace(/\s+/g, ' ').trim());
            }
        }
        form.classList.add('is-dropzone-ready');
    }

    function scheduleDropzone() {
        polishScanDropzone();
        window.setTimeout(polishScanDropzone, 0);
        window.setTimeout(polishScanDropzone, 250);
        window.setTimeout(polishScanDropzone, 800);
    }

    function closeVerdictSelect(wrap) {
        if (!wrap) {
            return;
        }
        wrap.classList.remove('is-open');
        var toggle = wrap.querySelector('.antivirus-verdict-select-toggle');
        var menu = wrap.querySelector('.antivirus-verdict-select-menu');
        if (toggle) {
            toggle.setAttribute('aria-expanded', 'false');
        }
        if (menu) {
            menu.hidden = true;
        }
    }

    function syncVerdictSelectLabel(wrap) {
        var select = wrap.querySelector('select');
        var valueEl = wrap.querySelector('.antivirus-verdict-select-value');
        if (!select || !valueEl) {
            return;
        }
        var option = select.options[select.selectedIndex];
        valueEl.textContent = option ? option.text : '';
        wrap.querySelectorAll('.antivirus-verdict-select-option').forEach(function(item) {
            var selected = item.getAttribute('data-value') === select.value;
            item.classList.toggle('is-selected', selected);
            item.setAttribute('aria-selected', selected ? 'true' : 'false');
        });
    }

    function enhanceVerdictSelects() {
        document.querySelectorAll('.antivirus-verdict-scanform select').forEach(function(select) {
            if (select.closest('[data-antivirus-verdict="select"]')) {
                return;
            }
            var wrap = document.createElement('div');
            wrap.className = 'antivirus-verdict-select';
            wrap.setAttribute('data-antivirus-verdict', 'select');
            select.parentNode.insertBefore(wrap, select);
            wrap.appendChild(select);
            select.classList.add('antivirus-verdict-select-native');
            select.setAttribute('tabindex', '-1');
            select.setAttribute('aria-hidden', 'true');

            var toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'antivirus-verdict-select-toggle';
            toggle.setAttribute('aria-haspopup', 'listbox');
            toggle.setAttribute('aria-expanded', 'false');
            var label = '';
            var fieldLabel = wrap.closest('.fitem');
            if (fieldLabel) {
                var title = fieldLabel.querySelector('.col-form-label, label');
                if (title) {
                    label = (title.textContent || '').trim();
                }
            }
            if (label) {
                toggle.setAttribute('aria-label', label);
            }

            var valueEl = document.createElement('span');
            valueEl.className = 'antivirus-verdict-select-value';
            toggle.appendChild(valueEl);
            var chevron = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            chevron.setAttribute('class', 'antivirus-verdict-select-chevron');
            chevron.setAttribute('width', '16');
            chevron.setAttribute('height', '16');
            chevron.setAttribute('viewBox', '0 0 24 24');
            chevron.setAttribute('fill', 'none');
            chevron.setAttribute('stroke', 'currentColor');
            chevron.setAttribute('stroke-width', '1.8');
            chevron.setAttribute('aria-hidden', 'true');
            var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path.setAttribute('d', 'M6 9l6 6 6-6');
            chevron.appendChild(path);
            toggle.appendChild(chevron);

            var menu = document.createElement('ul');
            menu.className = 'antivirus-verdict-select-menu';
            menu.setAttribute('role', 'listbox');
            menu.hidden = true;
            Array.prototype.forEach.call(select.options, function(option) {
                var item = document.createElement('li');
                item.className = 'antivirus-verdict-select-option';
                item.setAttribute('role', 'option');
                item.setAttribute('data-value', option.value);
                item.textContent = option.text;
                menu.appendChild(item);
            });

            wrap.appendChild(toggle);
            wrap.appendChild(menu);
            syncVerdictSelectLabel(wrap);
        });
    }

    applyTheme(storedTheme());

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            applyTheme(storedTheme());
            scheduleDropzone();
            enhanceVerdictSelects();
        });
    } else {
        scheduleDropzone();
        enhanceVerdictSelects();
    }

    document.addEventListener('click', function(event) {
        var selectWrap = event.target.closest('[data-antivirus-verdict="select"]');
        document.querySelectorAll('[data-antivirus-verdict="select"].is-open').forEach(function(openWrap) {
            if (openWrap !== selectWrap) {
                closeVerdictSelect(openWrap);
            }
        });
        if (selectWrap) {
            var option = event.target.closest('.antivirus-verdict-select-option');
            var toggle = event.target.closest('.antivirus-verdict-select-toggle');
            var select = selectWrap.querySelector('select');
            var menu = selectWrap.querySelector('.antivirus-verdict-select-menu');
            if (option && select && menu) {
                event.preventDefault();
                select.value = option.getAttribute('data-value') || '';
                syncVerdictSelectLabel(selectWrap);
                closeVerdictSelect(selectWrap);
                toggle = selectWrap.querySelector('.antivirus-verdict-select-toggle');
                if (toggle) {
                    toggle.focus();
                }
                return;
            }
            if (toggle && menu) {
                event.preventDefault();
                var willOpen = menu.hidden;
                if (willOpen) {
                    selectWrap.classList.add('is-open');
                    toggle.setAttribute('aria-expanded', 'true');
                    menu.hidden = false;
                } else {
                    closeVerdictSelect(selectWrap);
                }
                return;
            }
        }

        var themeToggle = event.target.closest('[data-antivirus-verdict="theme-toggle"]');
        if (themeToggle) {
            event.preventDefault();
            persistTheme(storedTheme() === 'light' ? 'dark' : 'light');
            return;
        }

        var dropzone = event.target.closest('.antivirus-verdict-dropzone');
        if (dropzone) {
            var form = dropzone.closest('.antivirus-verdict-scanform');
            if (!form) {
                return;
            }
            var onNativeChoose = event.target.closest('.fp-btn-choose, [id^="filepicker-button-"]');
            if (onNativeChoose) {
                var nativeId = filepickerClientId(onNativeChoose);
                if (nativeId && window.M && M.core_filepicker && M.core_filepicker.instances &&
                        M.core_filepicker.instances[nativeId] &&
                        typeof M.core_filepicker.instances[nativeId].show === 'function') {
                    event.preventDefault();
                    M.core_filepicker.instances[nativeId].show();
                }
                return;
            }
            event.preventDefault();
            openMoodleFilepicker(form);
            return;
        }

        var copyBtn = event.target.closest('[data-antivirus-verdict="copy-hash"]');
        if (copyBtn) {
            event.preventDefault();
            var row = copyBtn.closest('.antivirus-verdict-hash-row');
            var hashEl = row ? row.querySelector('.antivirus-verdict-hash') : null;
            var text = hashEl ? (hashEl.textContent || '').trim() : '';
            if (!text || !navigator.clipboard || !navigator.clipboard.writeText) {
                return;
            }
            navigator.clipboard.writeText(text).then(function() {
                copyBtn.classList.add('is-copied');
                copyBtn.innerHTML = CHECK_ICON;
                window.setTimeout(function() {
                    copyBtn.classList.remove('is-copied');
                    copyBtn.innerHTML = COPY_ICON;
                }, 1400);
            });
            return;
        }

        var dismiss = event.target.closest('[data-antivirus-verdict="dismiss-banner"]');
        if (dismiss) {
            event.preventDefault();
            var banner = dismiss.closest('.antivirus-verdict-banner');
            if (banner) {
                banner.hidden = true;
            }
            return;
        }

        var editKey = event.target.closest('[data-antivirus-verdict="edit-key"]');
        if (editKey) {
            event.preventDefault();
            var field = document.getElementById('antivirus-verdict-apikey-edit');
            var box = document.getElementById('antivirus-verdict-key-box');
            if (field) {
                field.hidden = false;
                field.focus();
            }
            if (box) {
                box.hidden = true;
            }
        }
    });

    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            document.querySelectorAll('[data-antivirus-verdict="select"].is-open').forEach(closeVerdictSelect);
        }
        if (event.key !== 'Enter' && event.key !== ' ') {
            return;
        }
        var dropzone = event.target.closest('.antivirus-verdict-dropzone');
        if (!dropzone || event.target !== dropzone) {
            return;
        }
        var form = dropzone.closest('.antivirus-verdict-scanform');
        if (!form) {
            return;
        }
        event.preventDefault();
        openMoodleFilepicker(form);
    });

    function initOverviewWidgets() {
        var root = document.querySelector('.antivirus-verdict-ov');
        if (!root) {
            return;
        }
        var wrap = root.querySelector('[data-antivirus-verdict="ov-period"]');
        var countEl = root.querySelector('[data-antivirus-verdict="ov-count"]');
        if (wrap && countEl) {
            wrap.querySelectorAll('.antivirus-verdict-ov-chip').forEach(function(chip) {
                chip.addEventListener('click', function() {
                    wrap.querySelectorAll('.antivirus-verdict-ov-chip').forEach(function(other) {
                        other.classList.remove('is-active');
                        other.setAttribute('aria-pressed', 'false');
                    });
                    chip.classList.add('is-active');
                    chip.setAttribute('aria-pressed', 'true');
                    if (chip.getAttribute('data-showing')) {
                        countEl.textContent = chip.getAttribute('data-showing');
                    }
                });
            });
        }
        var body = root.querySelector('[data-antivirus-verdict="ov-scans"]');
        if (!body) {
            return;
        }
        var headers = root.querySelectorAll('.antivirus-verdict-ov-sortable');
        var dir = {};
        function cellValue(row, colIndex, type) {
            var td = row.children[colIndex];
            if (!td) {
                return '';
            }
            if (type === 'time') {
                return td.getAttribute('data-ts') || '';
            }
            if (type === 'detect') {
                return parseFloat(td.getAttribute('data-detect') || '-1');
            }
            return td.textContent.trim().toLowerCase();
        }
        function sortByHeader(th, colIndex) {
            var type = th.getAttribute('data-sort');
            var asc = dir[colIndex] !== 'asc';
            dir = {};
            dir[colIndex] = asc ? 'asc' : 'desc';
            headers.forEach(function(header) {
                header.classList.remove('is-sorted');
                header.setAttribute('aria-sort', 'none');
                var arrow = header.querySelector('.antivirus-verdict-ov-sort');
                if (arrow) {
                    arrow.textContent = '↕';
                }
            });
            th.classList.add('is-sorted');
            th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');
            var sortedArrow = th.querySelector('.antivirus-verdict-ov-sort');
            if (sortedArrow) {
                sortedArrow.textContent = asc ? '↑' : '↓';
            }
            var rows = Array.prototype.slice.call(body.querySelectorAll('tr'));
            rows.sort(function(a, b) {
                var va = cellValue(a, colIndex, type);
                var vb = cellValue(b, colIndex, type);
                if (va < vb) {
                    return asc ? -1 : 1;
                }
                if (va > vb) {
                    return asc ? 1 : -1;
                }
                return 0;
            });
            rows.forEach(function(row) {
                body.appendChild(row);
            });
        }
        headers.forEach(function(th, colIndex) {
            th.addEventListener('click', function() {
                sortByHeader(th, colIndex);
            });
            th.addEventListener('keydown', function(event) {
                if (event.key !== 'Enter' && event.key !== ' ') {
                    return;
                }
                event.preventDefault();
                sortByHeader(th, colIndex);
            });
        });
    }

    function syncNavExpanded() {
        var toggle = document.getElementById('antivirus-verdict-navtoggle');
        var menubtn = document.querySelector('.antivirus-verdict-menubtn');
        if (!toggle) {
            return;
        }
        var expanded = toggle.checked ? 'true' : 'false';
        toggle.setAttribute('aria-expanded', expanded);
        if (menubtn) {
            menubtn.setAttribute('aria-expanded', expanded);
        }
    }

    function initNavDrawer() {
        var toggle = document.getElementById('antivirus-verdict-navtoggle');
        if (!toggle) {
            return;
        }
        syncNavExpanded();
        toggle.addEventListener('change', syncNavExpanded);
        document.addEventListener('keydown', function(event) {
            if (event.key !== 'Escape' || !toggle.checked) {
                return;
            }
            toggle.checked = false;
            syncNavExpanded();
        });
    }

    function initTeacherAccess() {
        var master = document.querySelector('[data-antivirus-verdict="teacher-access"]');
        var pages = document.getElementById('antivirus-verdict-teacher-pages');
        if (!master || !pages) {
            return;
        }
        var sync = function() {
            pages.hidden = !master.checked;
        };
        sync();
        master.addEventListener('change', sync);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            initOverviewWidgets();
            initNavDrawer();
            initTeacherAccess();
        });
    } else {
        initOverviewWidgets();
        initNavDrawer();
        initTeacherAccess();
    }
})();
