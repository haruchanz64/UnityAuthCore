using UnityAuthCore.Config;
using UnityAuthCore.Editor.UI;
using UnityEditor;
using UnityEditor.UIElements;
using UnityEngine.UIElements;

namespace UnityAuthCore.Editor.Inspectors
{
    /// <summary>
    /// Custom UI Toolkit inspector for <see cref="AuthFrameworkConfig"/> that adds a shortcut button
    /// to launch <see cref="AuthWorkbenchWindow"/> bound to the inspected config asset.
    /// </summary>
    [CustomEditor(typeof(AuthFrameworkConfig))]
    public sealed class AuthFrameworkConfigInspector : UnityEditor.Editor
    {
        /// <inheritdoc/>
        public override VisualElement CreateInspectorGUI()
        {
            var root = new VisualElement();
            var config = (AuthFrameworkConfig)target;

            var openBtn = new Button(() => AuthWorkbenchWindow.OpenWithConfig(config))
            {
                text = "Open in Auth & API Console"
            };
            openBtn.style.marginBottom = 8;
            openBtn.style.height = 28;
            root.Add(openBtn);

            InspectorElement.FillDefaultInspector(root, serializedObject, this);
            return root;
        }
    }
}
