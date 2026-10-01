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

    var KEY = 'antivirus_verdict_theme';
    var theme = 'dark';
    try {
        var stored = window.localStorage.getItem(KEY);
        if (stored === 'light' || stored === 'dark') {
            theme = stored;
        }
    } catch (e) {
        theme = 'dark';
    }
    document.documentElement.setAttribute('data-antivirus-verdict-theme', theme);
})();
