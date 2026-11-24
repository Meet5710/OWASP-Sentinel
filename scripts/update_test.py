with open('frontend/src/test/components.test.tsx', 'r', encoding='utf-8') as f:
    c = f.read()

c_norm = c.replace('\r\n', '\n')

old_test = """    // Verify library drawer is open
    expect(screen.getByText('~/target-assessment/Practice_Scripts')).toBeInTheDocument();
    expect(screen.getByText('407 Security Assessment Scripts')).toBeInTheDocument();
    expect(screen.getByText('Scanners')).toBeInTheDocument();
    expect(screen.getByText('Exploit Payloads')).toBeInTheDocument();
    expect(screen.getByText('Brute-force')).toBeInTheDocument();"""

new_test = """    // Verify library drawer is open
    expect(screen.getByText('~/target-assessment/Practice_Scripts')).toBeInTheDocument();
    expect(screen.getByText('407 Security Assessment Scripts')).toBeInTheDocument();
    expect(screen.getByText(/407 modular scripts • 0 subdirectories/i)).toBeInTheDocument();"""

assert old_test in c_norm, 'old_test not found'
c_norm = c_norm.replace(old_test, new_test)

with open('frontend/src/test/components.test.tsx', 'w', encoding='utf-8') as f:
    f.write(c_norm)

print('components.test.tsx updated successfully!')
