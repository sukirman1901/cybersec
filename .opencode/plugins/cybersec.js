/**
 * Cybersec plugin for OpenCode
 *
 * Injects cybersecurity bootstrap context.
 * Auto-registers skills directory + MCP server.
 */

import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const extractAndStripFrontmatter = (content) => {
  const match = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) return { frontmatter: {}, content };
  const frontmatterStr = match[1];
  const body = match[2];
  const frontmatter = {};
  for (const line of frontmatterStr.split('\n')) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim();
      const value = line.slice(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
      frontmatter[key] = value;
    }
  }
  return { frontmatter, content: body };
};

export const CybersecPlugin = async ({ client, directory }) => {
  const skillsDir = path.resolve(__dirname, '../../skills');
  const mcpsDir = path.resolve(__dirname, '../../mcp');

  const getBootstrapContent = () => {
    const skillPath = path.join(skillsDir, 'using-cybersec', 'SKILL.md');
    if (!fs.existsSync(skillPath)) return null;
    const fullContent = fs.readFileSync(skillPath, 'utf8');
    const { content } = extractAndStripFrontmatter(fullContent);
    return `<EXTREMELY_IMPORTANT>
You have CYBERSEC SUPERPOWERS.

**IMPORTANT: The using-cybersec skill content is included below. It is ALREADY LOADED - you are currently following it.**

${content}
</EXTREMELY_IMPORTANT>`;
  };

  return {
    config: async (config) => {
      config.skills = config.skills || {};
      config.skills.paths = config.skills.paths || [];
      if (!config.skills.paths.includes(skillsDir)) {
        config.skills.paths.push(skillsDir);
      }
      config.mcp = config.mcp || {};
      const venvPython = path.join(mcpsDir, '.venv', 'bin', 'python3');
      const pythonBin = fs.existsSync(venvPython) ? venvPython : 'python3';
      if (!config.mcp.cybersec) {
        config.mcp.cybersec = {
          type: 'local',
          command: [pythonBin, '-m', 'server'],
          cwd: mcpsDir,
          enabled: true,
        };
      }
    },
    'experimental.chat.messages.transform': async (_input, output) => {
      const bootstrap = getBootstrapContent();
      if (!bootstrap || !output.messages.length) return;
      const firstUser = output.messages.find(m => m.info.role === 'user');
      if (!firstUser || !firstUser.parts.length) return;
      if (firstUser.parts.some(p => p.type === 'text' && p.text.includes('CYBERSEC SUPERPOWERS'))) return;
      const ref = firstUser.parts[0];
      firstUser.parts.unshift({ ...ref, type: 'text', text: bootstrap });
    },
  };
};
