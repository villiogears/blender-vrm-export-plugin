import bpy
import os
import tempfile
import shutil
import struct
import json

bl_info = {
    "name": "VRM Exporter (with metadata)",
    "author": "elphadeal",
    "version": (0, 2, 0),
    "blender": (2, 80, 0),
    "location": "File > Export",
    "description": "Export to .vrm with basic VRM metadata injected into the GLB",
    "warning": "Creates VRM container with minimal metadata; does not validate full VRM spec.",
    "wiki_url": "",
    "tracker_url": "",
    "category": "Import-Export",
}


def _pad_to_4(data: bytes) -> bytes:
    pad = (-len(data)) % 4
    if pad:
        return data + (b' ' * pad)
    return data


def inject_vrm_extension_into_glb(glb_path: str, meta: dict) -> None:
    """Read a GLB, inject a minimal VRM extension into the JSON chunk, and overwrite the GLB.

    This function performs minimal edits: adds 'VRM' to extensionsUsed and inserts
    an 'VRM' object into the root 'extensions' with the provided meta under 'meta'.
    It is intentionally conservative to avoid breaking other data.
    """
    with open(glb_path, 'rb') as f:
        header = f.read(12)
        if len(header) < 12:
            raise ValueError('Invalid GLB: header too short')
        magic, version, length = struct.unpack('<4sII', header)
        if magic != b'glTF':
            raise ValueError('Not a GLB (magic mismatch)')

        # Read chunks
        json_chunk = None
        bin_chunk = None
        cursor = 12
        while cursor < length:
            f.seek(cursor)
            chunk_header = f.read(8)
            if len(chunk_header) < 8:
                break
            chunk_len, chunk_type = struct.unpack('<I4s', chunk_header)
            chunk_data = f.read(chunk_len)
            if chunk_type == b'JSON':
                json_chunk = chunk_data
            elif chunk_type == b'BIN\x00':
                bin_chunk = chunk_data
            cursor += 8 + chunk_len

    if json_chunk is None:
        raise ValueError('GLB has no JSON chunk')

    json_text = json_chunk.decode('utf-8')
    gltf = json.loads(json_text)

    # Ensure extensionsUsed
    ext_used = set(gltf.get('extensionsUsed', []))
    ext_used.add('VRM')
    gltf['extensionsUsed'] = list(ext_used)

    # Ensure extensions dict
    extensions = gltf.get('extensions', {})

    # Minimal VRM object structure. VRM spec is richer; we add the 'meta' section.
    vrm_obj = extensions.get('VRM', {})
    vrm_obj.setdefault('specVersion', '0.0')
    vrm_obj.setdefault('meta', {})

    # Populate meta fields from provided dict (only known keys)
    allowed_keys = [
        'title', 'version', 'author', 'contactInformation', 'reference',
        'allowedUserName', 'violentUsageName', 'sexualUsageName', 'commercialUsageName',
        'licenseName', 'otherPermissionUrl'
    ]
    for k in allowed_keys:
        if k in meta and meta[k] is not None:
            vrm_obj['meta'][k] = meta[k]

    extensions['VRM'] = vrm_obj
    gltf['extensions'] = extensions

    # Re-encode JSON chunk
    new_json = json.dumps(gltf, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    new_json_padded = _pad_to_4(new_json)

    # Rebuild GLB
    new_chunks = []
    # JSON chunk
    new_chunks.append((len(new_json_padded), b'JSON', new_json_padded))
    # BIN chunk (if existed)
    if bin_chunk is not None:
        new_chunks.append((len(bin_chunk), b'BIN\x00', bin_chunk))

    # Compute total length: 12 byte header + each chunk header (8) + chunk data
    total_length = 12 + sum(8 + c[0] for c in new_chunks)

    with open(glb_path, 'wb') as f:
        f.write(struct.pack('<4sII', b'glTF', 2, total_length))
        for ch_len, ch_type, ch_data in new_chunks:
            f.write(struct.pack('<I4s', ch_len, ch_type))
            f.write(ch_data)


def _coerce_val(v):
    """Coerce Blender operator/property values to JSON-serializable primitives."""
    try:
        # If it's already a plain str
        if isinstance(v, str):
            return v if v != '' else None
        # Some Blender properties are deferred; str() typically yields a sensible representation
        if v is None:
            return None
        return str(v)
    except Exception:
        return None


class EXPORT_OT_vrm_full(bpy.types.Operator):
    """Export selected objects as VRM with metadata injected"""
    bl_idname = "export_scene.vrm_full"
    bl_label = "Export VRM (.vrm) with metadata"
    bl_options = {'REGISTER', 'UNDO'}

    filename_ext = bpy.props.StringProperty(default='.vrm', options={'HIDDEN'})
    filter_glob = bpy.props.StringProperty(default='*.vrm', options={'HIDDEN'})
    filepath = bpy.props.StringProperty(name='File Path', subtype='FILE_PATH')
    export_selected = bpy.props.BoolProperty(name='Selected Objects', default=True)

    # VRM meta fields
    meta_title = bpy.props.StringProperty(name='Title', default='')
    meta_version = bpy.props.StringProperty(name='Version', default='')
    meta_author = bpy.props.StringProperty(name='Author', default='')
    meta_contact = bpy.props.StringProperty(name='Contact', default='')
    meta_reference = bpy.props.StringProperty(name='Reference', default='')
    meta_allowed_user = bpy.props.EnumProperty(
        name='Allowed User',
        items=[('のみ', 'Only Author', ''), ('所有者', 'Only Author', ''), ('Everyone', 'Everyone', '')],
        default='Everyone'
    )

    def execute(self, context):
        if not hasattr(bpy.ops.export_scene, 'gltf'):
            self.report({'ERROR'}, 'glTF exporter not available in this Blender build')
            return {'CANCELLED'}

        # Determine extension string safely
        try:
            ext = self.filename_ext
            if not isinstance(ext, str):
                ext = '.vrm'
        except Exception:
            ext = '.vrm'

        # Create a secure temporary GLB file for the exporter to write to.
        tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.glb')
        tmp_glb = tmpf.name
        tmpf.close()

        # Determine final target path. Prefer the concrete value returned by
        # self.as_keywords() (Blender will populate this after the file dialog).
        candidate_fp = None
        try:
            kw = self.as_keywords()
            candidate_fp = kw.get('filepath', None)
        except Exception:
            candidate_fp = getattr(self, 'filepath', None)

        if isinstance(candidate_fp, str) and candidate_fp.strip() != '':
            target_path = bpy.path.ensure_ext(candidate_fp, ext)
        else:
            target_path = os.path.join(os.path.expanduser('~'), 'export' + ext)

        prev_selected = None
        prev_active = None
        try:
            # Some Blender builds' glTF exporter may not accept 'export_selected' keyword.
            # If user requested selected-only export, perform selection toggling around the export call.
            if self.export_selected:
                prev_selected = list(context.selected_objects)
                prev_active = context.view_layer.objects.active
                # deselect all, then reselect the previously selected objects to ensure exporter respects selection
                bpy.ops.object.select_all(action='DESELECT')
                for o in prev_selected:
                    try:
                        o.select_set(True)
                    except Exception:
                        pass
                if prev_selected:
                    try:
                        context.view_layer.objects.active = prev_selected[0]
                    except Exception:
                        pass

            bpy.ops.export_scene.gltf(filepath=tmp_glb, export_format='GLB')

        except Exception as e:
            # attempt to restore selection if we modified it
            try:
                if prev_selected is not None:
                    bpy.ops.object.select_all(action='DESELECT')
                    for o in prev_selected:
                        try:
                            o.select_set(True)
                        except Exception:
                            pass
                    try:
                        context.view_layer.objects.active = prev_active
                    except Exception:
                        pass
            except Exception:
                pass
            self.report({'ERROR'}, f'glTF export failed: {e}')
            return {'CANCELLED'}

        meta = {
            'title': _coerce_val(self.meta_title),
            'version': _coerce_val(self.meta_version),
            'author': _coerce_val(self.meta_author),
            'contactInformation': _coerce_val(self.meta_contact),
            'reference': _coerce_val(self.meta_reference),
            # Note: coerce enum/property to simple string; VRM spec expects specific enum values in real implementations
            'allowedUserName': _coerce_val(self.meta_allowed_user),
        }

        try:
            inject_vrm_extension_into_glb(tmp_glb, meta)
        except Exception as e:
            self.report({'ERROR'}, f'Failed to inject VRM metadata: {e}')
            if os.path.exists(tmp_glb):
                try:
                    os.remove(tmp_glb)
                except Exception:
                    pass
            return {'CANCELLED'}

        try:
            shutil.copyfile(tmp_glb, target_path)
        except Exception as e:
            self.report({'ERROR'}, f'Failed to write .vrm: {e}')
            return {'CANCELLED'}
        finally:
            try:
                os.remove(tmp_glb)
            except Exception:
                pass

        self.report({'INFO'}, f'Exported VRM with metadata to: {target_path}')
        return {'FINISHED'}

    def invoke(self, context, event):
        # Ensure filepath is a plain string before showing file selector
        # Only set a default filepath if it's explicitly empty or None.
        try:
            fp = getattr(self, 'filepath', None)
            if fp is None or (isinstance(fp, str) and fp == ''):
                try:
                    ext = self.filename_ext
                    if not isinstance(ext, str):
                        ext = '.vrm'
                except Exception:
                    ext = '.vrm'
                self.filepath = os.path.join(os.path.expanduser('~'), 'export' + ext)
            # If fp is a deferred property, leave it alone so Blender fills it from the UI selection.
        except Exception:
            self.filepath = os.path.join(os.path.expanduser('~'), 'export' + '.vrm')
        context.window_manager.fileselect_add(self)
        return {'RUNNING_MODAL'}


def menu_func_export(self, context):
    self.layout.operator(EXPORT_OT_vrm_full.bl_idname, text='VRM (.vrm) with metadata')


classes = (
    EXPORT_OT_vrm_full,
)


def register():
    for cls in classes:
        bpy.utils.register_class(cls)
    bpy.types.TOPBAR_MT_file_export.append(menu_func_export)


def unregister():
    bpy.types.TOPBAR_MT_file_export.remove(menu_func_export)
    for cls in reversed(classes):
        bpy.utils.unregister_class(cls)


if __name__ == '__main__':
    register()

