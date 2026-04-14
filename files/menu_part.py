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
