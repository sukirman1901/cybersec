/**
 * Cybersec plugin for OpenCode
 *
 * Dual-compatible with OpenCode V1 and V2.
 *
 * V1 (OpenCode 1.x): loaded via named export CybersecPlugin — provides a
 * config hook (skills path + MCP server registration) and
 * experimental.chat.messages.transform for bootstrap injection.
 *
 * V2 (OpenCode 2.x): loaded via default export { id, setup } — setup()
 * registers skills natively via ctx.skill.transform(), registers the MCP
 * server via ctx.mcp.transform(), and injects bootstrap context via
 * ctx.session.hook("context").
 *
 * No external dependencies — pure JavaScript works in both V1 and V2 without
 * installing @opencode-ai/plugin.
 */

import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const skillsDir = path.resolve(__dirname, '../../skills');
const mcpsDir = path.resolve(__dirname, '../../mcp');

// Frontmatter extraction (plain `key: value` lines, quoted values, YAML block
// scalar markers with continuation lines, CRLF). Not a full YAML parser —
// nested maps flatten into their parent key's value, which is fine for the
// name/description fields consumed here.
const extractAndStripFrontmatter = (content) => {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return { frontmatter: {}, content };

  const frontmatterStr = match[1];
  const body = match[2];
  const frontmatter = {};
  let lastKey = null;

  for (const rawLine of frontmatterStr.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0 && !/^\s/.test(line)) {
      const key = line.slice(0, colonIdx).trim();
      const value = line.slice(colonIdx + 1).trim();
      frontmatter[key] = /^(>[+-]?|\|[+-]?)$/.test(value) ? '' : value;
      lastKey = key;
    } else if (lastKey !== null && line.trim() !== '') {
      frontmatter[lastKey] = `${frontmatter[lastKey]} ${line.trim()}`.trim();
    }
  }

  for (const key of Object.keys(frontmatter)) {
    frontmatter[key] = frontmatter[key].replace(/^(["'])([\s\S]*)\1$/, '$2');
  }

  return { frontmatter, content: body };
};

// Module-level cache: the SKILL.md file does not change during a session, so
// read + parse it once instead of on every agent step (the context hook fires
// on every step). null = file missing.
let _bootstrapCache; // undefined = not loaded yet

const getBootstrapContent = () => {
  if (_bootstrapCache !== undefined) return _bootstrapCache;

  const skillPath = path.join(skillsDir, 'using-cybersec', 'SKILL.md');
  if (!fs.existsSync(skillPath)) {
    _bootstrapCache = null;
    return null;
  }

  const fullContent = fs.readFileSync(skillPath, 'utf8');
  const { content } = extractAndStripFrontmatter(fullContent);

  _bootstrapCache = `<EXTREMELY_IMPORTANT>
You have CYBERSEC SUPERPOWERS.

**IMPORTANT: The using-cybersec skill content is included below. It is ALREADY LOADED - you are currently following it.**

${content}
</EXTREMELY_IMPORTANT>`;

  return _bootstrapCache;
};

// Read every skills/<name>/SKILL.md once, at registration time.
const collectSkills = () => {
  const skills = [];
  if (!fs.existsSync(skillsDir)) return skills;
  for (const entry of fs.readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const skillPath = path.join(skillsDir, entry.name, 'SKILL.md');
    if (!fs.existsSync(skillPath)) continue;
    const { frontmatter, content } = extractAndStripFrontmatter(fs.readFileSync(skillPath, 'utf8'));
    skills.push({
      id: entry.name,
      name: frontmatter.name || entry.name,
      ...(frontmatter.description ? { description: frontmatter.description } : {}),
      // Skill.Info renamed its required file field `location` -> `path` in
      // OpenCode v2.0.4.
      path: skillPath,
      content,
    });
  }
  return skills;
};

/**
 * V1 Plugin Function (named export + default.server)
 *
 * Used by V1 (OpenCode 1.x): discovered via named export scanning.
 * Provides: config hook (V1 skills path + MCP registration) + bootstrap
 * injection (experimental.chat.messages.transform).
 */
export const CybersecPlugin = async ({ client, directory }) => {
  return {
    config: async (config) => {
      // V2: skills is a flat array — skip, setup() handles V2 skill registration
      if (Array.isArray(config.skills)) return;

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

/**
 * V2 Setup Function (default.setup)
 *
 * Called by V2 PluginSupervisor. Performs three things:
 *
 * 1. Registers every skills/<name>/SKILL.md as a native Skill.Info object
 *    via ctx.skill.transform((draft) => draft.add(info)).
 * 2. Registers the cybersec MCP server via ctx.mcp.transform() unless the
 *    user already configured one (same guard as the V1 config hook).
 * 3. Injects bootstrap context via ctx.session.hook("context"), the V2
 *    equivalent of V1's experimental.chat.messages.transform.
 */
async function setup(ctx) {
  // V1 also invokes default.setup with a V1-shaped ctx that lacks the
  // skill/session/mcp domains. Detect it and return quietly — V1 is served
  // entirely by the CybersecPlugin named export.
  if (!ctx || !ctx.skill || typeof ctx.skill.transform !== 'function' || !ctx.session || typeof ctx.session.hook !== 'function') {
    return;
  }

  // 1. Register skills
  try {
    const skills = collectSkills();
    await ctx.skill.transform((draft) => {
      // draft.add() decodes against the host's Skill.Info schema and throws
      // synchronously on a mismatch; an escaping throw escalates to a
      // hard-disable of the entire plugin. Contain failures per skill so one
      // rejected payload skips that skill instead of killing skills AND
      // bootstrap.
      for (const skill of skills) {
        try {
          draft.add(skill);
        } catch (err) {
          console.error(`[cybersec] skill "${skill.id}" rejected by host, skipping:`, err);
        }
      }
    });
  } catch (err) {
    // Never break plugin activation: one failing plugin takes down the whole
    // V2 generation (including provider/catalog plugins => no models in TUI).
    console.error('[cybersec] skill registration failed:', err);
  }

  // 2. Register MCP server unless one is already configured
  try {
    if (ctx.mcp && typeof ctx.mcp.transform === 'function') {
      await ctx.mcp.transform((editor) => {
        if (editor.get('cybersec')) return;
        const venvPython = path.join(mcpsDir, '.venv', 'bin', 'python3');
        const pythonBin = fs.existsSync(venvPython) ? venvPython : 'python3';
        editor.set('cybersec', {
          type: 'local',
          command: [pythonBin, '-m', 'server'],
          cwd: mcpsDir,
          enabled: true,
        });
      });
    }
  } catch (err) {
    console.error('[cybersec] MCP registration failed:', err);
  }

  // 3. Inject bootstrap into first user message via V2 session context hook
  try {
    await ctx.session.hook('context', async (event) => {
      try {
        const bootstrap = getBootstrapContent();
        if (!bootstrap || !event.messages || !event.messages.length) return;
        const firstUser = event.messages.find(m => m.role === 'user');
        if (firstUser && (!firstUser.content || !firstUser.content.length)) return;
        if (firstUser?.content.some(p => p.type === 'text' && p.text && p.text.includes('CYBERSEC SUPERPOWERS'))) return;

        // Native compaction can leave only an opaque checkpoint. Keep it
        // intact and append the transient bootstrap as a user message.
        if (firstUser) {
          firstUser.content.unshift({ type: 'text', text: bootstrap });
        } else {
          event.messages.push({ role: 'user', content: [{ type: 'text', text: bootstrap }] });
        }
      } catch (err) {
        // Never let hook callback errors break the request pipeline.
        console.error('[cybersec] context hook failed:', err);
      }
    });
  } catch (err) {
    console.error('[cybersec] session hook registration failed:', err);
  }
}

/**
 * Default Export: { id, server, setup }
 *
 * V2 PluginSupervisor reads { id, setup }.
 * V1 reads named export CybersecPlugin.
 * server() is exported for V1 object-entrypoint compatibility.
 */
export default {
  id: 'cybersec',
  server: CybersecPlugin,
  setup,
};
