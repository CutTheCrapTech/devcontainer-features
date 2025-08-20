import threading
import time
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from auto_secrets.core.singleton import SingletonMeta


class TestSingletonMeta(unittest.TestCase):
  """Test cases for SingletonMeta metaclass."""

  def setUp(self) -> None:
    """Clear singleton instances before each test."""
    SingletonMeta._instances.clear()

  def tearDown(self) -> None:
    """Clean up after each test."""
    SingletonMeta._instances.clear()


class TestBasicSingletonBehavior(TestSingletonMeta):
  """Test basic singleton functionality."""

  def test_single_instance_creation(self) -> None:
    """Test that only one instance is created for a class."""

    class TestSingleton(metaclass=SingletonMeta):
      def __init__(self) -> None:
        self.value = "test"

    instance1: TestSingleton = TestSingleton()
    instance2: TestSingleton = TestSingleton()

    self.assertIs(instance1, instance2)
    self.assertEqual(id(instance1), id(instance2))

  def test_multiple_classes_separate_instances(self) -> None:
    """Test that different classes have separate singleton instances."""

    class SingletonA(metaclass=SingletonMeta):
      def __init__(self) -> None:
        self.name = "A"

    class SingletonB(metaclass=SingletonMeta):
      def __init__(self) -> None:
        self.name = "B"

    instance_a1: SingletonA = SingletonA()
    instance_a2: SingletonA = SingletonA()
    instance_b1: SingletonB = SingletonB()
    instance_b2: SingletonB = SingletonB()

    # Same class instances should be identical
    self.assertIs(instance_a1, instance_a2)
    self.assertIs(instance_b1, instance_b2)

    # Different class instances should be different
    self.assertIsNot(instance_a1, instance_b1)
    self.assertEqual(instance_a1.name, "A")
    self.assertEqual(instance_b1.name, "B")

  def test_init_called_only_once(self) -> None:
    """Test that __init__ is called only once."""
    init_call_count = 0

    class TestSingleton(metaclass=SingletonMeta):
      def __init__(self) -> None:
        nonlocal init_call_count
        init_call_count += 1
        self.value = init_call_count

    instance1: TestSingleton = TestSingleton()
    instance2: TestSingleton = TestSingleton()
    instance3: TestSingleton = TestSingleton()

    self.assertEqual(init_call_count, 1)
    self.assertEqual(instance1.value, 1)
    self.assertEqual(instance2.value, 1)
    self.assertEqual(instance3.value, 1)
    self.assertIs(instance1, instance2)
    self.assertIs(instance2, instance3)

  def test_singleton_with_arguments(self) -> None:
    """Test singleton behavior with constructor arguments."""

    class ConfigSingleton(metaclass=SingletonMeta):
      def __init__(self, config_name: str, debug: bool = False) -> None:
        self.config_name = config_name
        self.debug = debug

    # First instance with arguments
    instance1: ConfigSingleton = ConfigSingleton("production", debug=True)

    # Subsequent instances (arguments should be ignored)
    instance2: ConfigSingleton = ConfigSingleton("development", debug=False)
    instance3: ConfigSingleton = ConfigSingleton()  # type: ignore[call-arg]

    self.assertIs(instance1, instance2)
    self.assertIs(instance2, instance3)

    # Should retain the values from the first instantiation
    self.assertEqual(instance1.config_name, "production")
    self.assertEqual(instance1.debug, True)
    self.assertEqual(instance2.config_name, "production")
    self.assertEqual(instance2.debug, True)


class TestThreadSafety(TestSingletonMeta):
  """Test thread safety of the singleton."""

  def test_concurrent_instance_creation(self) -> None:
    """Test that concurrent access creates only one instance."""
    instances: list[Any] = []
    creation_times: list[float] = []
    barrier = threading.Barrier(10)  # Wait for all threads to be ready

    class SlowSingleton(metaclass=SingletonMeta):
      def __init__(self) -> None:
        # Simulate slow initialization
        time.sleep(0.1)
        self.creation_time = time.time()

    def create_instance() -> None:
      barrier.wait()  # All threads start at the same time
      instance = SlowSingleton()
      instances.append(instance)
      creation_times.append(instance.creation_time)

    threads: list[threading.Thread] = []
    for _ in range(10):
      thread = threading.Thread(target=create_instance)
      threads.append(thread)
      thread.start()

    for thread in threads:
      thread.join()

    # All instances should be the same object
    self.assertEqual(len(instances), 10)
    first_instance = instances[0]
    for instance in instances:
      self.assertIs(instance, first_instance)

    # All creation times should be the same (only one __init__ call)
    unique_creation_times: set[float] = set(creation_times)
    self.assertEqual(len(unique_creation_times), 1)

  def test_race_condition_prevention(self) -> None:
    """Test that race conditions are properly handled."""
    call_order: list[str] = []

    class RaceTestSingleton(metaclass=SingletonMeta):
      def __init__(self) -> None:
        call_order.append(f"init_start_{threading.current_thread().name}")
        time.sleep(0.05)  # Small delay to increase chance of race condition
        call_order.append(f"init_end_{threading.current_thread().name}")

    def create_instance(thread_name: str) -> Any:
      return RaceTestSingleton()

    threads: list[threading.Thread] = []
    results: list[Any] = []

    def worker(name: str) -> None:
      result = create_instance(name)
      results.append(result)

    # Create multiple threads
    for i in range(5):
      thread = threading.Thread(target=worker, args=(f"Thread-{i}",), name=f"Thread-{i}")
      threads.append(thread)

    # Start all threads
    for thread in threads:
      thread.start()

    # Wait for all threads to complete
    for thread in threads:
      thread.join()

    # Verify all results are the same instance
    self.assertEqual(len(results), 5)
    for result in results:
      self.assertIs(result, results[0])

    # Verify that __init__ was called exactly once
    init_starts = [call for call in call_order if call.startswith("init_start")]
    init_ends = [call for call in call_order if call.startswith("init_end")]
    self.assertEqual(len(init_starts), 1)
    self.assertEqual(len(init_ends), 1)


class TestInheritanceBehavior(TestSingletonMeta):
  """Test singleton behavior with inheritance."""

  def test_inheritance_separate_singletons(self) -> None:
    """Test that parent and child classes have separate singleton instances."""

    class BaseSingleton(metaclass=SingletonMeta):
      def __init__(self) -> None:
        self.type = "base"

    class DerivedSingleton(BaseSingleton):
      def __init__(self) -> None:
        super().__init__()
        self.type = "derived"

    base_instance1: BaseSingleton = BaseSingleton()
    base_instance2: BaseSingleton = BaseSingleton()
    derived_instance1: DerivedSingleton = DerivedSingleton()
    derived_instance2: DerivedSingleton = DerivedSingleton()

    # Same class instances should be identical
    self.assertIs(base_instance1, base_instance2)
    self.assertIs(derived_instance1, derived_instance2)

    # Different class instances should be different
    self.assertIsNot(base_instance1, derived_instance1)
    self.assertEqual(base_instance1.type, "base")
    self.assertEqual(derived_instance1.type, "derived")

  def test_multiple_inheritance_levels(self) -> None:
    """Test singleton behavior with multiple inheritance levels."""

    class GrandParent(metaclass=SingletonMeta):
      def __init__(self) -> None:
        self.level = "grandparent"

    class Parent(GrandParent):
      def __init__(self) -> None:
        super().__init__()
        self.level = "parent"

    class Child(Parent):
      def __init__(self) -> None:
        super().__init__()
        self.level = "child"

    gp1: GrandParent = GrandParent()
    gp2: GrandParent = GrandParent()
    p1: Parent = Parent()
    p2: Parent = Parent()
    c1: Child = Child()
    c2: Child = Child()

    # Each class should have its own singleton
    self.assertIs(gp1, gp2)
    self.assertIs(p1, p2)
    self.assertIs(c1, c2)

    # Different classes should have different instances
    self.assertIsNot(gp1, p1)
    self.assertIsNot(p1, c1)
    self.assertIsNot(gp1, c1)

    # Verify correct initialization
    self.assertEqual(gp1.level, "grandparent")
    self.assertEqual(p1.level, "parent")
    self.assertEqual(c1.level, "child")


class TestEdgeCases(TestSingletonMeta):
  """Test edge cases and error conditions."""

  def test_exception_during_init(self) -> None:
    """Test behavior when __init__ raises an exception."""

    class FailingSingleton(metaclass=SingletonMeta):
      def __init__(self, should_fail: bool = True) -> None:
        if should_fail:
          raise ValueError("Initialization failed")
        self.initialized = True

    # First attempt should raise exception
    with self.assertRaises(ValueError):
      FailingSingleton()

    # Class should not be in instances dict after failed initialization
    self.assertNotIn(FailingSingleton, SingletonMeta._instances)

    # Second attempt should also raise exception (no cached failed instance)
    with self.assertRaises(ValueError):
      FailingSingleton()

    # Successful initialization should work
    instance: FailingSingleton = FailingSingleton(should_fail=False)
    self.assertTrue(instance.initialized)

    # Subsequent calls should return the same instance
    instance2: FailingSingleton = FailingSingleton(should_fail=True)  # should_fail ignored
    self.assertIs(instance, instance2)

  def test_class_attributes_not_shared(self) -> None:
    """Test that class attributes are not affected by singleton behavior."""

    class SingletonWithClassAttr(metaclass=SingletonMeta):
      class_attr = "original"

      def __init__(self) -> None:
        self.instance_attr = "instance"

    # Modify class attribute
    SingletonWithClassAttr.class_attr = "modified"

    instance1: SingletonWithClassAttr = SingletonWithClassAttr()
    instance2: SingletonWithClassAttr = SingletonWithClassAttr()

    self.assertIs(instance1, instance2)
    self.assertEqual(instance1.class_attr, "modified")
    self.assertEqual(instance2.class_attr, "modified")
    self.assertEqual(SingletonWithClassAttr.class_attr, "modified")

  def test_pickle_serialization(self) -> None:
    """Test that singleton instances can be pickled and unpickled."""
    import pickle

    class PicklableSingleton(metaclass=SingletonMeta):
      def __init__(self) -> None:
        self.value = 42

    original: PicklableSingleton = PicklableSingleton()

    # Serialize and deserialize
    serialized: bytes = pickle.dumps(original)
    deserialized: PicklableSingleton = pickle.loads(serialized)

    # Note: After unpickling, the deserialized object might not be the same instance
    # This is expected behavior and depends on how __reduce__ is implemented
    self.assertEqual(deserialized.value, 42)

  def test_weakref_compatibility(self) -> None:
    """Test that singleton instances work with weak references."""
    import weakref

    class WeakRefSingleton(metaclass=SingletonMeta):
      def __init__(self) -> None:
        self.value = "test"

    instance: WeakRefSingleton = WeakRefSingleton()
    weak_ref: weakref.ReferenceType[WeakRefSingleton] = weakref.ref(instance)

    self.assertIs(weak_ref(), instance)
    self.assertEqual(weak_ref().value, "test")  # type: ignore[union-attr]


class TestMetaclassInternals(TestSingletonMeta):
  """Test internal behavior of the metaclass."""

  def test_instances_dict_structure(self) -> None:
    """Test the structure of the _instances dictionary."""

    class TestSingleton1(metaclass=SingletonMeta):
      pass

    class TestSingleton2(metaclass=SingletonMeta):
      pass

    # Initially empty
    initial_count = len(SingletonMeta._instances)

    # Create instances
    instance1: TestSingleton1 = TestSingleton1()
    instance2: TestSingleton2 = TestSingleton2()

    # Check instances dict
    self.assertEqual(len(SingletonMeta._instances), initial_count + 2)
    self.assertIn(TestSingleton1, SingletonMeta._instances)
    self.assertIn(TestSingleton2, SingletonMeta._instances)
    self.assertIs(SingletonMeta._instances[TestSingleton1], instance1)
    self.assertIs(SingletonMeta._instances[TestSingleton2], instance2)

  @patch("threading.Lock")
  def test_lock_usage(self, mock_lock_class: MagicMock) -> None:
    """Test that the lock is properly used."""
    mock_lock_instance = MagicMock()
    mock_lock_class.return_value = mock_lock_instance

    # Create a new metaclass instance to use the mocked lock
    class TestMeta(type):
      _instances: dict[type, Any] = {}
      _lock = mock_lock_class()

      def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        with cls._lock:
          if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]

    class TestSingleton(metaclass=TestMeta):
      def __init__(self) -> None:
        self.value = "test"

    # Create instances
    instance1: TestSingleton = TestSingleton()
    instance2: TestSingleton = TestSingleton()

    # Verify lock was used
    self.assertTrue(mock_lock_instance.__enter__.called)
    self.assertTrue(mock_lock_instance.__exit__.called)

    # Verify singleton behavior still works
    self.assertIs(instance1, instance2)


# Pytest style parametrized tests
@pytest.mark.parametrize("num_threads", [2, 5, 10, 20])
def test_concurrent_creation_parametrized(num_threads: int) -> None:
  """Parametrized test for concurrent instance creation."""
  # Clear instances before test
  SingletonMeta._instances.clear()

  class ConcurrentSingleton(metaclass=SingletonMeta):
    def __init__(self) -> None:
      time.sleep(0.01)  # Small delay
      self.thread_id = threading.current_thread().ident

  instances: list[Any] = []
  threads: list[threading.Thread] = []

  def create_instance() -> None:
    instance = ConcurrentSingleton()
    instances.append(instance)

  # Create and start threads
  for _ in range(num_threads):
    thread = threading.Thread(target=create_instance)
    threads.append(thread)
    thread.start()

  # Wait for all threads
  for thread in threads:
    thread.join()

  # Verify all instances are the same
  assert len(instances) == num_threads
  for instance in instances:
    assert instance is instances[0]


@pytest.mark.parametrize(
  "init_args,init_kwargs",
  [
    ((), {}),
    (("arg1",), {}),
    (("arg1", "arg2"), {}),
    ((), {"key": "value"}),
    (("arg1",), {"key": "value"}),
  ],
)
def test_singleton_with_various_arguments(init_args: tuple, init_kwargs: dict) -> None:
  """Test singleton behavior with various argument combinations."""
  # Clear instances before test
  SingletonMeta._instances.clear()

  class ArgumentSingleton(metaclass=SingletonMeta):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
      self.args = args
      self.kwargs = kwargs

  # First instance with arguments
  instance1: ArgumentSingleton = ArgumentSingleton(*init_args, **init_kwargs)

  # Second instance (arguments should be ignored)
  instance2: ArgumentSingleton = ArgumentSingleton("different", "args", different="kwargs")

  assert instance1 is instance2
  assert instance1.args == init_args
  assert instance1.kwargs == init_kwargs


if __name__ == "__main__":
  # Run tests using unittest
  unittest.main()
