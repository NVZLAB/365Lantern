using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
namespace Lantern.Desktop;

public partial class CollectionLantern : UserControl
{
    private Storyboard? animation;
    public CollectionLantern() { InitializeComponent(); Unloaded += (_, _) => Stop(); }
    private void Stop() { animation?.Remove(this); animation = null; }
    private void VisibilityChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        Stop();
        if (!IsVisible || !SystemParameters.ClientAreaAnimation || SystemParameters.HighContrast) return;
        animation = new Storyboard();
        void Animate(string target, string property, double seconds, params double[] values)
        {
            var track = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromSeconds(seconds), RepeatBehavior = RepeatBehavior.Forever };
            for (int i = 0; i < values.Length; i++) track.KeyFrames.Add(new SplineDoubleKeyFrame(values[i], KeyTime.FromTimeSpan(TimeSpan.FromSeconds(seconds * i / (values.Length - 1))), new KeySpline(.4, 0, .6, 1)));
            Storyboard.SetTargetName(track, target); Storyboard.SetTargetProperty(track, new PropertyPath(property)); animation.Children.Add(track);
        }
        Animate("FlameScale", "ScaleY", 2.4, 1, 1.08, .94, 1.05, .98, 1);
        Animate("FlameScale", "ScaleX", 2.4, 1, .95, 1.04, .98, 1.02, 1);
        Animate("FlameSway", "AngleX", 2.4, 0, -3, 2, -1, 3, 0);
        Animate("Flame", "Opacity", 2.4, .9, 1, .8, .96, .86, .9);
        Animate("Glow", "Opacity", 2.4, .04, .09, .04);
        Animate("DotOne", "Opacity", 1.8, 1, .25, .25, 1);
        Animate("DotTwo", "Opacity", 1.8, .25, 1, .25, .25);
        Animate("DotThree", "Opacity", 1.8, .25, .25, 1, .25);
        animation.Begin(this, true);
    }
}
