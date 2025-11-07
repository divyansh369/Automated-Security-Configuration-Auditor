import json 

def generate_html_report(result, host, timestamp, machine):
    html = f"""
        <html>
        <head>
            <title>Security Audit Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                }}
                h1 {{
                    text-align: center;
                    color: #333;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    border: 1px solid #ccc;
                    padding: 10px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .PASS {{
                    background-color: #c8e6c9;
                }}
                .FAIL {{
                    background-color: #ffcdd2;
                }}
            </style>
        </head>
        <body>
            <h1>System Security Audit Report</h1>
            <p><b>Hostname:</b> {host}</p>
            <p><b>Timestamp:</b> {timestamp}</p>
            <p><b>Machine:</b> {machine}</p>
            <table>
                <thead>
                    <tr>
                        <th>Rule Name</th>
                        <th>Status</th>
                        <th>Expected</th>
                        <th>Actual</th>
                    </tr>
                </thead>
                <tbody>
    """

    for r in result:
        html += f"""
                <tr class="{r['status']}">
                    <td>{r['name']}</td>
                    <td>{r['status']}</td>
                    <td>{r['expected']}</td>
                    <td>{r['actual_value']}</td>
                </tr>
        """

    html += """
            </tbody>
            </table>
        </body>
        </html>
    """

    with open('security_audit_report.html', 'w') as f:
        f.write(html)

    print("✅ HTML report generated: security_audit_report.html")