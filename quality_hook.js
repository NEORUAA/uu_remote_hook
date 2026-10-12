'use strict';

let listeners = [];
let installed = false;
let overrides = 0;
let activeProfile = null;

function verifyTarget(module, target) {
    if (!Number.isSafeInteger(target.rva) || target.rva < 0 || target.rva + 32 > module.size) {
        throw new Error('Invalid target RVA.');
    }
    const address = module.base.add(target.rva);
    const expected = target.signature.match(/.{2}/g).map(value => parseInt(value, 16));
    if (expected.length !== 32) throw new Error('Invalid target signature.');
    const actual = Array.from(new Uint8Array(address.readByteArray(32)));
    if (!expected.every((value, i) => actual[i] === value)) {
        throw new Error('Loaded code differs from the inspected image; refusing to attach.');
    }
    return address;
}

function status() {
    return {installed, overrides, pid: Process.id, version: activeProfile ? activeProfile.version : null};
}

function stop() {
    listeners.forEach(listener => listener.detach());
    listeners = [];
    installed = false;
    Interceptor.flush();
    return {installed, overrides};
}

rpc.exports = {
    install(moduleName, profile) {
        if (installed) throw new Error('A hook is already installed in this script.');
        if (Process.arch !== 'x64' || profile.max_quality !== 4 || profile.quality_offset !== 4 ||
            profile.codec_offset !== 12 || profile.result_offset !== 24) {
            throw new Error('Unsupported ABI or capability record layout.');
        }
        const module = Process.getModuleByName(moduleName);
        const matcher = verifyTarget(module, profile.matcher);
        const presenter = profile.presenter ? verifyTarget(module, profile.presenter) : null;
        try {
            listeners.push(Interceptor.attach(matcher, {
                onEnter(args) {
                    this.output = args[1];
                    this.chroma = args[2].toInt32();
                    this.hdr = args[3].toInt32() & 0xff;
                },
                onLeave(retval) {
                    if (this.chroma !== 1 || this.hdr !== 0 || this.output.isNull() || !retval.equals(this.output)) return;
                    const out = this.output;
                    const range = Process.findRangeByAddress(out);
                    if (!range || !range.protection.includes('w') || out.add(28).compare(range.base.add(range.size)) > 0) return;
                    const quality = out.add(4).readS32();
                    const codec = out.add(12).readS32();
                    const result = out.add(24).readS32();
                    if (out.readS32() !== 1 || out.add(8).readU8() !== 0 || result !== 0 ||
                        ![1, 2].includes(codec) || quality < 1 || quality >= 4) return;
                    out.add(4).writeS32(4);
                    overrides += 1;
                    send({event: 'quality_cap_raised', from: quality, to: 4, codec, overrides});
                }
            }));
            if (presenter) {
                listeners.push(Interceptor.attach(presenter, {
                    onEnter(args) { this.uiQuality = args[2].toInt32(); },
                    onLeave(retval) {
                        send({event: 'quality_request_checked', ui_quality: this.uiQuality, accepted: (retval.toInt32() & 0xff) !== 0});
                    }
                }));
            }
            installed = true;
            activeProfile = profile;
            Interceptor.flush();
            send({event: 'hook_ready', pid: Process.id, version: profile.version,
                matcher_rva: profile.matcher.rva, presenter_diagnostics: presenter !== null});
            return status();
        } catch (error) {
            stop();
            throw error;
        }
    },
    status,
    stop
};
