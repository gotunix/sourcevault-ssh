# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 GOTUNIX Networks <code@gotunix.net>
# SPDX-FileCopyrightText: 2026 Justin Ovens <code@gotunix.net>
# ----------------------------------------------------------------------------------------------- #
#                 $$$$$$\   $$$$$$\ $$$$$$$$\ $$\\   $$\ $$\\   $$\ $$$$$$\ $$\\   $$\               #
#                $$  __$$\ $$  __$$\\__$$  __|$$ |  $$ |$$$\\  $$ |\\_$$  _|$$ |  $$ |              #
#                $$ /  \\__|$$ /  $$ |  $$ |   $$ |  $$ |$$$$\\ $$ |  $$ |  \\$$\\ $$  |              #
#                $$ |$$$$\\ $$ |  $$ |  $$ |   $$ |  $$ |$$ $$\\$$ |  $$ |   \\$$$$  /               #
#                $$ |\\_$$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ \\$$$$ |  $$ |   $$  $$<                #
#                $$ |  $$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ |\\$$$ |  $$ |  $$  /\\$$\\               #
#                \\$$$$$$  | $$$$$$  |  $$ |   \\$$$$$$  |$$ | \\$$ |$$$$$$\\ $$ /  $$ |              #
#                 \\______/  \\______/   \\__|    \\______/ \\__|  \\__|\\______|\\__|  \\__|              #
# ----------------------------------------------------------------------------------------------- #
# Copyright (C) GOTUNIX Networks                                                                  #
# Copyright (C) Justin Ovens                                                                      #
# ----------------------------------------------------------------------------------------------- #
# This program is free software: you can redistribute it and/or modify                            #
# it under the terms of the GNU Affero General Public License as                                  #
# published by the Free Software Foundation, either version 3 of the                              #
# License, or (at your option) any later version.                                                 #
#                                                                                                 #
# This program is distributed in the hope that it will be useful,                                 #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                                 #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   #
# GNU Affero General Public License for more details.                                             #
#                                                                                                 #
# You should have received a copy of the GNU Affero General Public License                        #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.                          #
# ----------------------------------------------------------------------------------------------- #

def draw_confirmation(stdscr, title, fields):
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    draw_header(stdscr, title)

    y = 4
    stdscr.addstr(y, 2, "Press Enter to confirm choices, F12 to go back.", curses.color_pair(COLOR_GREEN_PAIR))
    y += 2

    for field in fields:
        label = field['label'].replace('.', '').strip()
        value = field['value']
        
        # Display label and value
        display_str = f"{label}: {value}"
        
        # Check specific field types if needed, or just display generic
        if not value and not field.get('required', False):
             display_str = f"{label}: (Empty)"
        
        if y < height - 2:
             stdscr.addstr(y, 4, display_str, curses.color_pair(COLOR_GREEN_PAIR))
             y += 1

    draw_footer(stdscr, {"F3": "Exit", "F12": "Back", "Enter": "Confirm"})
    stdscr.refresh()
